// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#pragma once

#include <string>
#include <random>
#include <cstring>
#include <cstdint>
#include <utility>



namespace Crypt{
class ELGamal{
//// ================================== ////
//// ============== Data ============== ////
//// ================================== ////
private:
  size_t p = 1;
  size_t g = 0;
  size_t x = 0;
  size_t y = 0;
  bool p_is_prime = false;
  bool g_is_valid = false;
  bool x_is_valid = false;

  std::string str_print = "";

  void* message = nullptr;
  size_t message_size = 0;

  void* cipher = nullptr;
  size_t cipher_size = 0;



//// ======================================= ////
//// ============== Functions ============== ////
//// ======================================= ////
//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
public:
  // core
  ELGamal() noexcept;
  ELGamal(size_t p, size_t g, size_t x) noexcept;
  ~ELGamal() noexcept;
  // copy
  ELGamal(const ELGamal& second) noexcept;
  ELGamal& operator=(const ELGamal& second) noexcept;
  // move
  ELGamal(ELGamal&& second) noexcept;
  ELGamal& operator=(ELGamal&& second) noexcept;

//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
  size_t getP() const noexcept;
  void setP(size_t p) noexcept;

  size_t getG() const noexcept;
  void setG(size_t g) noexcept;

  size_t getX() const noexcept;
  void setX(size_t x) noexcept;

  size_t getY() const noexcept;

  bool pIsPrime() const noexcept;
  bool gIsValid() const noexcept;
  bool xIsValid() const noexcept;

  void setMessage(const void* data, size_t size) noexcept;
  std::pair<const void*, size_t> getMessage() const noexcept;

  void setCipher(const void* data, size_t size) noexcept;
  std::pair<const void*, size_t> getCipher() const noexcept;

//// ========================= ////
//// ========= Crypt ========= ////
//// ========================= ////
public:
  void crypt() noexcept;
  void encrypt() noexcept;

//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
public:
  bool operator==(const ELGamal& second) const noexcept;
  bool operator!=(const ELGamal& second) const noexcept;

//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
private:
  bool check_is_prime(size_t val);
  bool generatorTest(size_t val) noexcept;
  void calculateY() noexcept;
  size_t generateK() noexcept;
  size_t modPow(size_t base, size_t exp, size_t mod) noexcept;

//// =================== ////
//// ====== Print ====== ////
//// =================== ////
public:
  std::string& str();
  const char* c_str();
};
};