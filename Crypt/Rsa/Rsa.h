// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#pragma once
#include <string>
#include <array>
#include <math.h>
#include <random>
#include <stdexcept>
#include <cstring>



namespace Crypt{
class Rsa{
//// ================================== ////
//// ============== Data ============== ////
//// ================================== ////
private:
  size_t p = 1;
  size_t q = 1;
  bool p_is_prime = false;
  bool q_is_prime = false;
  bool e_is_valid = false;
  size_t n = 1;
  size_t fib_n = 0;
  size_t e = 0;
  size_t d = 0;
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
  Rsa() noexcept;
  Rsa(size_t p, size_t q) noexcept;
  ~Rsa() noexcept;

  // copy
  Rsa(const Rsa& second) noexcept;
  Rsa& operator=(const Rsa& second) noexcept;
  
  // move
  Rsa(Rsa&& second) noexcept;
  Rsa& operator=(Rsa&& second) noexcept;

//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
  size_t getP() const noexcept;
  void setP(size_t p) noexcept;
  size_t getQ() const noexcept;
  void setQ(size_t q) noexcept;
  size_t getE() const noexcept;
  void setE(size_t e) noexcept;
  bool pIsPrime() const noexcept;
  bool qIsPrime() const noexcept;
  bool eIsValid() const noexcept;

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
  bool operator==(const Rsa& second) const noexcept;
  bool operator!=(const Rsa& second) const noexcept;

//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
private:
  bool check_is_prime(size_t val);
  void calculateFibN();
  bool gcdTest(size_t a, size_t b) noexcept;
  void calculateD() noexcept;
  size_t modPow(size_t base, size_t exp, size_t mod) noexcept;

//// =================== ////
//// ====== Print ====== ////
//// =================== ////
public:
  std::string& str();
  const char* c_str();
};
};
