// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



//////////////////////////
///////// sha256 /////////
//////////////////////////
//// IDEA ////
// SHA-256 is a one-way hashing method.
// Once data is hashed, nobody can reverse it.
// Used for password hashing, integrity checks,
// and cryptographic key operations.

//// How it works: ////
// The input is padded: first a '1' bit, then zeros,
// and finally the message length (64 bits).
// The padded message is split into 512-bit blocks.
//
// For each block:
//   * Create a 64-word message schedule (W[0..63])
//   * Initialize 8 working variables (a..h) with H0..H7
//   * Run 64 rounds using ROTR, Σ0, Σ1, CH, Maj,
//     and 64 constant values derived from prime numbers
//   * Add the results back into H0..H7
//
// If the message has more blocks, repeat.

//// TL;TR ////
// * Pad message and split into 512-bit blocks
// * For each block, run 64 rounds of mixing
// * Final H0..H7 values form the 256-bit hash



#pragma once
#include <string.h>
#include <stdint.h>
#include <string>
#include <array>



namespace Crypt{
class Sha{
//// ================================== ////
//// ============== Data ============== ////
//// ================================== ////
private:
  void* data = nullptr;
  size_t data_size = 0;
  std::array<uint8_t, 32> hash = {0};
  bool hashed = false;



//// ======================================= ////
//// ============== Functions ============== ////
//// ======================================= ////
//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
public:
  // core
  Sha() noexcept;
  ~Sha() noexcept;
  // copy
  Sha(const Sha& second) noexcept;
  Sha& operator=(const Sha& second) noexcept;
  // move
  Sha(Sha&& second) noexcept;
  Sha& operator=(Sha&& second) noexcept;

//// =========================== ////
//// ===== Getters/Setters ===== ////
//// =========================== ////
public:
  void setData(const void* data, size_t size);
  const std::array<uint8_t, 32>& getHash();

//// =========================== ////
//// ========= Helpers ========= ////
//// =========================== ////
private:  
  void hashData(const void* data, size_t size, uint8_t* hash);
  void hashBlock(const uint8_t* block, uint32_t H[8]);
  void ROTR(char data[4], char out[4], unsigned int k);
  
  void bigSigma0(char data[4], char out[4]);
  void bigSigma1(char data[4], char out[4]);
  
  void ch(char x[4], char y[4], char z[4], char out[4]);
  void maj(char x[4], char y[4], char z[4], char out[4]);
};
};
