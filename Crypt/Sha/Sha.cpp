// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "Sha.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
// core
Crypt::Sha::Sha() noexcept {};



Crypt::Sha::~Sha() noexcept {
  delete[] static_cast<uint8_t*>(data);
};



// copy
Crypt::Sha::Sha(const Sha &second) noexcept
  : data_size(second.data_size),
    hash(second.hash),
    hashed(second.hashed) {

  if(second.data && second.data_size){
    uint8_t* buffer = new uint8_t[second.data_size];
    memcpy(buffer, second.data, second.data_size);
    data = buffer;
  };
};



Crypt::Sha &Crypt::Sha::operator=(const Sha &second) noexcept {
  if(this == &second) return *this;

  uint8_t* buffer = nullptr;

  if(second.data && second.data_size){
    buffer = new uint8_t[second.data_size];
    memcpy(buffer, second.data, second.data_size);
  };

  delete[] static_cast<uint8_t*>(data);

  data = buffer;
  data_size = second.data_size;
  hash = second.hash;
  hashed = second.hashed;

  return *this;
};



// move
Crypt::Sha::Sha(Sha &&second) noexcept
  : data(second.data),
    data_size(second.data_size),
    hash(std::move(second.hash)),
    hashed(second.hashed) {

  second.data = nullptr;
  second.data_size = 0;
  second.hashed = false;
};



Crypt::Sha &Crypt::Sha::operator=(Sha &&second) noexcept {
  if(this == &second) return *this;

  delete[] static_cast<uint8_t*>(data);

  data = second.data;
  data_size = second.data_size;
  hash = std::move(second.hash);
  hashed = second.hashed;

  second.data = nullptr;
  second.data_size = 0;
  second.hashed = false;

  return *this;
};



//// =========================== ////
//// ===== Getters/Setters ===== ////
//// =========================== ////
void Crypt::Sha::setData(const void* data, size_t size){
  if(this->data){
    delete[] static_cast<uint8_t*>(this->data);
    this->data = nullptr;
  };

  data_size = 0;
  hashed = false;

  if(!data || size == 0) return;

  uint8_t* buffer = new uint8_t[size];
  memcpy(buffer, data, size);

  this->data = buffer;
  data_size = size;
};



const std::array<uint8_t, 32>& Crypt::Sha::getHash(){
  if(!hashed){
    hashData(data, data_size, hash.data());
    hashed = true;
  };

  return hash;
};



//// =========================== ////
//// ========= Helpers ========= ////
//// =========================== ////
void Crypt::Sha::hashData(const void* data, size_t size, uint8_t* hash){
  const uint8_t* bytes = static_cast<const uint8_t*>(data);

  uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };

  size_t offset = 0;

  while(size - offset >= 64){
    hashBlock(bytes + offset, H);
    offset += 64;
  };

  uint8_t final_blocks[128] = {0};

  size_t remaining = size - offset;

  if(remaining)
    memcpy(final_blocks, bytes + offset, remaining);

  final_blocks[remaining] = 0x80;

  uint64_t bit_length = static_cast<uint64_t>(size) * 8;

  size_t final_size = remaining < 56 ? 64 : 128;

  final_blocks[final_size - 8] = (bit_length >> 56) & 0xFF;
  final_blocks[final_size - 7] = (bit_length >> 48) & 0xFF;
  final_blocks[final_size - 6] = (bit_length >> 40) & 0xFF;
  final_blocks[final_size - 5] = (bit_length >> 32) & 0xFF;
  final_blocks[final_size - 4] = (bit_length >> 24) & 0xFF;
  final_blocks[final_size - 3] = (bit_length >> 16) & 0xFF;
  final_blocks[final_size - 2] = (bit_length >> 8) & 0xFF;
  final_blocks[final_size - 1] = bit_length & 0xFF;

  hashBlock(final_blocks, H);

  if(final_size == 128) hashBlock(final_blocks + 64, H);

  for(size_t i = 0; i < 8; i++){
    hash[i * 4 + 0] = (H[i] >> 24) & 0xFF;
    hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
    hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
    hash[i * 4 + 3] = H[i] & 0xFF;
  };
};



void Crypt::Sha::hashBlock(const uint8_t* block, uint32_t H[8]){
  static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };

  uint32_t W[64] = {0};

  for(size_t i = 0; i < 16; i++){
    W[i] =
      (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
      (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
      (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
       static_cast<uint32_t>(block[i * 4 + 3]);
  };

  auto rotr = [](uint32_t x, uint32_t n){
    return (x >> n) | (x << (32 - n));
  };

  for(size_t i = 16; i < 64; i++){
    uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
    uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);

    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
  };

  uint32_t a = H[0];
  uint32_t b = H[1];
  uint32_t c = H[2];
  uint32_t d = H[3];
  uint32_t e = H[4];
  uint32_t f = H[5];
  uint32_t g = H[6];
  uint32_t h = H[7];

  for(size_t i = 0; i < 64; i++){
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t temp1 = h + S1 + ch + K[i] + W[i];

    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  };

  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;
};



void Crypt::Sha::ROTR(char data[4], char out[4], unsigned int k) {
  uint32_t x = ((uint32_t)(uint8_t)data[0] << 24) |
                ((uint32_t)(uint8_t)data[1] << 16) |
                ((uint32_t)(uint8_t)data[2] << 8)  |
                ((uint32_t)(uint8_t)data[3]);

  uint32_t rot = (x >> k) | (x << (32 - k));

  out[0] = (rot >> 24) & 0xFF;
  out[1] = (rot >> 16) & 0xFF;
  out[2] = (rot >> 8)  & 0xFF;
  out[3] = rot & 0xFF;
};



void Crypt::Sha::bigSigma0(char data[4], char out[4]) {
  char r1[4] = {0};
  char r2[4] = {0};
  char r3[4] = {0};

  ROTR(data, r1, 2);
  ROTR(data, r2, 13);
  ROTR(data, r3, 22);

  uint32_t r1_x = ((uint32_t)(uint8_t)r1[0] << 24) |
                  ((uint32_t)(uint8_t)r1[1] << 16) |
                  ((uint32_t)(uint8_t)r1[2] << 8)  |
                  ((uint32_t)(uint8_t)r1[3]);

  uint32_t r2_x = ((uint32_t)(uint8_t)r2[0] << 24) |
                  ((uint32_t)(uint8_t)r2[1] << 16) |
                  ((uint32_t)(uint8_t)r2[2] << 8)  |
                  ((uint32_t)(uint8_t)r2[3]);

  uint32_t r3_x = ((uint32_t)(uint8_t)r3[0] << 24) |
                  ((uint32_t)(uint8_t)r3[1] << 16) |
                  ((uint32_t)(uint8_t)r3[2] << 8)  |
                  ((uint32_t)(uint8_t)r3[3]);

  uint32_t o_x = r1_x ^ r2_x ^ r3_x;

  out[0] = (o_x >> 24) & 0xFF;
  out[1] = (o_x >> 16) & 0xFF;
  out[2] = (o_x >> 8)  & 0xFF;
  out[3] =  o_x & 0xFF;
};



void Crypt::Sha::bigSigma1(char data[4], char out[4]){
  char r1[4] = {0};
  char r2[4] = {0};
  char r3[4] = {0};

  ROTR(data, r1, 6);
  ROTR(data, r2, 11);
  ROTR(data, r3, 25);

  uint32_t r1_x = ((uint32_t)(uint8_t)r1[0] << 24) |
                  ((uint32_t)(uint8_t)r1[1] << 16) |
                  ((uint32_t)(uint8_t)r1[2] << 8)  |
                  ((uint32_t)(uint8_t)r1[3]);

  uint32_t r2_x = ((uint32_t)(uint8_t)r2[0] << 24) |
                  ((uint32_t)(uint8_t)r2[1] << 16) |
                  ((uint32_t)(uint8_t)r2[2] << 8)  |
                  ((uint32_t)(uint8_t)r2[3]);

  uint32_t r3_x = ((uint32_t)(uint8_t)r3[0] << 24) |
                  ((uint32_t)(uint8_t)r3[1] << 16) |
                  ((uint32_t)(uint8_t)r3[2] << 8)  |
                  ((uint32_t)(uint8_t)r3[3]);

  uint32_t o_x = r1_x ^ r2_x ^ r3_x;

  out[0] = (o_x >> 24) & 0xFF;
  out[1] = (o_x >> 16) & 0xFF;
  out[2] = (o_x >> 8)  & 0xFF;
  out[3] =  o_x & 0xFF;
};



void Crypt::Sha::ch(char x[4], char y[4], char z[4], char out[4]) {
  uint32_t rx = ((uint32_t)(uint8_t)x[0] << 24) |
                  ((uint32_t)(uint8_t)x[1] << 16) |
                  ((uint32_t)(uint8_t)x[2] << 8)  |
                  ((uint32_t)(uint8_t)x[3]);

  uint32_t ry = ((uint32_t)(uint8_t)y[0] << 24) |
                  ((uint32_t)(uint8_t)y[1] << 16) |
                  ((uint32_t)(uint8_t)y[2] << 8)  |
                  ((uint32_t)(uint8_t)y[3]);

  uint32_t rz = ((uint32_t)(uint8_t)z[0] << 24) |
                  ((uint32_t)(uint8_t)z[1] << 16) |
                  ((uint32_t)(uint8_t)z[2] << 8)  |
                  ((uint32_t)(uint8_t)z[3]);

  uint32_t o_x = (rx & ry) ^ ((~rx) & rz);

  out[0] = (o_x >> 24) & 0xFF;
  out[1] = (o_x >> 16) & 0xFF;
  out[2] = (o_x >> 8)  & 0xFF;
  out[3] =  o_x & 0xFF;
};



void Crypt::Sha::maj(char x[4], char y[4], char z[4], char out[4]) {
  uint32_t rx = ((uint32_t)(uint8_t)x[0] << 24) |
                  ((uint32_t)(uint8_t)x[1] << 16) |
                  ((uint32_t)(uint8_t)x[2] << 8)  |
                  ((uint32_t)(uint8_t)x[3]);

  uint32_t ry = ((uint32_t)(uint8_t)y[0] << 24) |
                  ((uint32_t)(uint8_t)y[1] << 16) |
                  ((uint32_t)(uint8_t)y[2] << 8)  |
                  ((uint32_t)(uint8_t)y[3]);

  uint32_t rz = ((uint32_t)(uint8_t)z[0] << 24) |
                  ((uint32_t)(uint8_t)z[1] << 16) |
                  ((uint32_t)(uint8_t)z[2] << 8)  |
                  ((uint32_t)(uint8_t)z[3]);

  uint32_t o_x = (rx & ry) ^ (rx & rz) ^ (ry & rz);

  out[0] = (o_x >> 24) & 0xFF;
  out[1] = (o_x >> 16) & 0xFF;
  out[2] = (o_x >> 8)  & 0xFF;
  out[3] =  o_x & 0xFF;
};
