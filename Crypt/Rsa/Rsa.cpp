// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "Rsa.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
// core
Crypt::Rsa::Rsa() noexcept {};



Crypt::Rsa::Rsa(size_t p, size_t q) noexcept
  :p(p), q(q) {
  p_is_prime = check_is_prime(p);
  q_is_prime = check_is_prime(q);
  calculateFibN();
};



Crypt::Rsa::~Rsa() noexcept {
  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(cipher);
};



// copy
Crypt::Rsa::Rsa(const Rsa &second) noexcept
  : p(second.p), q(second.q),
    n(second.n), fib_n(second.fib_n),
    e(second.e), d(second.d),
    p_is_prime(second.p_is_prime),
    q_is_prime(second.q_is_prime),
    e_is_valid(second.e_is_valid) {
  setMessage(second.message, second.message_size);
  setCipher(second.cipher, second.cipher_size);
};



Crypt::Rsa& Crypt::Rsa::operator=(const Rsa& second) noexcept {
  if(this == &second) return *this;

  p = second.p; 
  q = second.q;
  n = second.n; 
  fib_n = second.fib_n;
  e = second.e; 
  d = second.d;
  p_is_prime = second.p_is_prime;
  q_is_prime = second.q_is_prime; 
  e_is_valid = second.e_is_valid;
  
  setMessage(second.message, second.message_size);
  setCipher(second.cipher, second.cipher_size); 
  
  return *this;
};



// move
Crypt::Rsa::Rsa(Rsa &&second) noexcept
  : p(std::move(second.p)), q(std::move(second.q)),
    n(std::move(second.n)), fib_n(std::move(second.fib_n)),
    e(std::move(second.e)), d(std::move(second.d)),
    p_is_prime(std::move(second.p_is_prime)),
    q_is_prime(std::move(second.q_is_prime)),
    e_is_valid(second.e_is_valid),
    message(std::move(second.message)),
    message_size(std::move(second.message_size)),
    cipher(std::move(second.cipher)),
    cipher_size(std::move(second.cipher_size)) {
  second.message = nullptr;
  second.cipher = nullptr;
  second.message_size = 0;
  second.cipher_size = 0;
};



Crypt::Rsa& Crypt::Rsa::operator=(Rsa&& second) noexcept {
  if(this == &second) return *this;

  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(cipher);

  p = std::move(second.p); 
  q = std::move(second.q);
  n = std::move(second.n); 
  fib_n = std::move(second.fib_n);
  e = std::move(second.e);
  d = std::move(second.d);
  p_is_prime = std::move(second.p_is_prime);
  q_is_prime = std::move(second.q_is_prime);
  e_is_valid = std::move(second.e_is_valid);

  message = std::move(second.message);
  cipher = std::move(second.cipher);
  message_size = std::move(second.message_size);
  cipher_size = std::move(second.cipher_size);

  second.message = nullptr;
  second.cipher = nullptr;
  second.message_size = 0;
  second.cipher_size = 0;
  
  return *this;
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
size_t Crypt::Rsa::getP() const noexcept {
  return p;
};



void Crypt::Rsa::setP(size_t p) noexcept {
  p_is_prime = false;
  this->p = p;
  p_is_prime = check_is_prime(this->p);
  calculateFibN();
  setE(e);
};



size_t Crypt::Rsa::getQ() const noexcept {
  return q;
};



void Crypt::Rsa::setQ(size_t q) noexcept {
  q_is_prime = false;
  this->q = q;
  q_is_prime = check_is_prime(this->q);
  calculateFibN();
  setE(e);
};



size_t Crypt::Rsa::getE() const noexcept {
  return e;
};



void Crypt::Rsa::setE(size_t e) noexcept {
  d = 0;
  this->e = 0;
  e_is_valid = false;

  if (e >= fib_n || e <= 1) return;
  if (!gcdTest(e, fib_n)) return;

  this->e = e;
  e_is_valid = true;

  calculateD();
};



bool Crypt::Rsa::pIsPrime() const noexcept {
  return p_is_prime;
};



bool Crypt::Rsa::qIsPrime() const noexcept {
  return q_is_prime;
};



bool Crypt::Rsa::eIsValid() const noexcept{
  return e_is_valid;
};



void Crypt::Rsa::setMessage(const void *data, size_t size) noexcept {
  if (data == nullptr || size == 0) {
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    message_size = 0;
    return;
  };

  auto* copy = new unsigned char[size];
  std::memcpy(copy, data, size);

  delete[] static_cast<unsigned char*>(message);

  message = copy;
  message_size = size;
};



std::pair<const void *, size_t> Crypt::Rsa::getMessage() const noexcept {
  return {message, message_size};
};



void Crypt::Rsa::setCipher(const void *data, size_t size) noexcept {
  if (data == nullptr || size == 0) {
    delete[] static_cast<unsigned char*>(cipher);
    cipher = nullptr;
    cipher_size = 0;
    return;
  };

  auto* copy = new unsigned char[size];
  std::memcpy(copy, data, size);

  delete[] static_cast<unsigned char*>(cipher);

  cipher = copy;
  cipher_size = size;
};



std::pair<const void *, size_t> Crypt::Rsa::getCipher() const noexcept {
  return {cipher, cipher_size};
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
void Crypt::Rsa::crypt() noexcept {
  if (!p_is_prime || !q_is_prime || !e_is_valid) return;
  if (message == nullptr || message_size == 0) return;

  delete[] static_cast<unsigned char*>(cipher);

  cipher = nullptr;
  cipher_size = 0;

  constexpr size_t block_size = sizeof(uint32_t);

  auto* data = new unsigned char[message_size * block_size];

  const auto* msg = static_cast<const unsigned char*>(message);

  for (size_t i = 0; i < message_size; ++i) {
    uint32_t encrypted = static_cast<uint32_t>(modPow(static_cast<size_t>(msg[i]), e, n));
    std::memcpy(data + i * block_size, &encrypted, block_size);
  };

  cipher = data;
  cipher_size = message_size * block_size;
};



void Crypt::Rsa::encrypt() noexcept {
  if (!p_is_prime || !q_is_prime || !e_is_valid) return;
  if (cipher == nullptr || cipher_size == 0) return;

  constexpr size_t block_size = sizeof(uint32_t);

  if (cipher_size % block_size != 0) return;

  const size_t message_length = cipher_size / block_size;

  const auto* encrypted = static_cast<const unsigned char*>(cipher);

  auto* data = new unsigned char[message_length];

  for (size_t i = 0; i < message_length; ++i) {
    uint32_t block;
    std::memcpy(&block, encrypted + i * block_size, block_size);
    data[i] = static_cast<unsigned char>(modPow(block, d, n));
  };

  delete[] static_cast<unsigned char*>(message);

  message = data;
  message_size = message_length;
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
bool Crypt::Rsa::operator==(const Rsa& second) const noexcept {
  if(p != second.p) return false;
  if(q != second.q) return false;
  if(n != second.n) return false;
  if(fib_n != second.fib_n) return false;
  if(e != second.e) return false;
  if(d != second.d) return false;

  return true;
};



bool Crypt::Rsa::operator!=(const Rsa& second) const noexcept {
  return !(*this == second);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
bool Crypt::Rsa::check_is_prime(size_t val) {
  if (val < 2) return false;

  if (val == 2 || val == 3) return true;

  if (val % 2 == 0 || val % 3 == 0) return false;

  for (size_t i = 5; i <= val / i; i += 6)
    if (val % i == 0 || val % (i + 2) == 0)
      return false;

  return true;
};



void Crypt::Rsa::calculateFibN(){
  if(p <= 0 || q <= 0 || p == q) {
    n = 0;
    fib_n = 0;
    return;
  };

  n = p * q;
  fib_n = (p - 1) * (q - 1);
};



bool Crypt::Rsa::gcdTest(size_t a, size_t b) noexcept{
  while (b != 0) {
    const size_t temp = b;
    b = a % b;
    a = temp;
  };

  return a == 1;
};



void Crypt::Rsa::calculateD() noexcept{
  d = 0;
  int64_t t = 0;
  int64_t new_t = 1;

  int64_t r = static_cast<int64_t>(fib_n);
  int64_t new_r = static_cast<int64_t>(e);

  while (new_r != 0) {
    const int64_t quotient = r / new_r;

    const int64_t temp_t = t;
    t = new_t;
    new_t = temp_t - quotient * new_t;

    const int64_t temp_r = r;
    r = new_r;
    new_r = temp_r - quotient * new_r;
  }

  if (r != 1) return;
  if (t < 0) t += static_cast<int64_t>(fib_n);

  d = static_cast<size_t>(t);
};



size_t Crypt::Rsa::modPow(size_t base, size_t exp, size_t mod) noexcept {
  size_t result = 1;
  base %= mod;

  while (exp > 0) {
    if (exp & 1) result = (result * base) % mod;
    exp >>= 1;
    if (exp) base = (base * base) % mod;
  };

  return result;
};



//// =================== ////
//// ====== Print ====== ////
//// =================== ////
std::string& Crypt::Rsa::str(){
  str_print = "Rsa(p = "+ std::to_string(p) +", q = "+ std::to_string(q) +", n = "+ std::to_string(n) +", fib_n = " + std::to_string(fib_n) +", e = " + std::to_string(e) +", d = "+ std::to_string(d) + ");";
  return str_print;
};



const char* Crypt::Rsa::c_str(){
  return str().c_str();
};
