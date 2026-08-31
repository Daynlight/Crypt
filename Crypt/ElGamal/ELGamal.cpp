// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "ElGamal.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
Crypt::ELGamal::ELGamal() noexcept {};



Crypt::ELGamal::ELGamal(size_t p, size_t g, size_t x) noexcept {
  setP(p);
  setG(g);
  setX(x);
};



Crypt::ELGamal::~ELGamal() noexcept {
  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(cipher);
};



Crypt::ELGamal::ELGamal(const ELGamal& second) noexcept
  : p(second.p), g(second.g), x(second.x), y(second.y),
    p_is_prime(second.p_is_prime), g_is_valid(second.g_is_valid), x_is_valid(second.x_is_valid) {
  setMessage(second.message, second.message_size);
  setCipher(second.cipher, second.cipher_size);
};



Crypt::ELGamal& Crypt::ELGamal::operator=(const ELGamal& second) noexcept {
  if(this == &second) return *this;

  p = second.p;
  g = second.g;
  x = second.x;
  y = second.y;

  p_is_prime = second.p_is_prime;
  g_is_valid = second.g_is_valid;
  x_is_valid = second.x_is_valid;

  setMessage(second.message, second.message_size);
  setCipher(second.cipher, second.cipher_size);

  return *this;
};



Crypt::ELGamal::ELGamal(ELGamal&& second) noexcept
  : p(std::move(second.p)), g(std::move(second.g)),
    x(std::move(second.x)), y(std::move(second.y)),
    p_is_prime(std::move(second.p_is_prime)),
    g_is_valid(std::move(second.g_is_valid)),
    x_is_valid(std::move(second.x_is_valid)),
    message(std::move(second.message)),
    message_size(std::move(second.message_size)),
    cipher(std::move(second.cipher)),
    cipher_size(std::move(second.cipher_size)) {

  second.message = nullptr;
  second.cipher = nullptr;
  second.message_size = 0;
  second.cipher_size = 0;
};



Crypt::ELGamal& Crypt::ELGamal::operator=(ELGamal&& second) noexcept {
  if(this == &second) return *this;

  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(cipher);

  p = std::move(second.p);
  g = std::move(second.g);
  x = std::move(second.x);
  y = std::move(second.y);

  p_is_prime = std::move(second.p_is_prime);
  g_is_valid = std::move(second.g_is_valid);
  x_is_valid = std::move(second.x_is_valid);

  message = std::move(second.message);
  message_size = std::move(second.message_size);

  cipher = std::move(second.cipher);
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
size_t Crypt::ELGamal::getP() const noexcept {
  return p;
};



void Crypt::ELGamal::setP(size_t p) noexcept {
  const size_t old_g = g;
  const size_t old_x = x;

  this->p = p;
  p_is_prime = check_is_prime(p);

  g = 0;
  x = 0;
  y = 0;

  g_is_valid = false;
  x_is_valid = false;

  if(!p_is_prime) return;

  setG(old_g);
  setX(old_x);
};



size_t Crypt::ELGamal::getG() const noexcept {
  return g;
};



void Crypt::ELGamal::setG(size_t g) noexcept {
  this->g = 0;
  y = 0;
  g_is_valid = false;

  if(!p_is_prime) return;
  if(g <= 1 || g >= p) return;
  if(!generatorTest(g)) return;

  this->g = g;
  g_is_valid = true;

  if(x_is_valid) calculateY();
};



size_t Crypt::ELGamal::getX() const noexcept {
  return x;
};



void Crypt::ELGamal::setX(size_t x) noexcept {
  this->x = 0;
  y = 0;
  x_is_valid = false;

  if(!p_is_prime || !g_is_valid) return;
  if(x == 0 || x >= p - 1) return;

  this->x = x;
  x_is_valid = true;

  calculateY();
};



size_t Crypt::ELGamal::getY() const noexcept {
  return y;
};



bool Crypt::ELGamal::pIsPrime() const noexcept {
  return p_is_prime;
};



bool Crypt::ELGamal::gIsValid() const noexcept {
  return g_is_valid;
};



bool Crypt::ELGamal::xIsValid() const noexcept {
  return x_is_valid;
};



void Crypt::ELGamal::setMessage(const void* data, size_t size) noexcept {
  if(data == nullptr || size == 0) {
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



std::pair<const void*, size_t> Crypt::ELGamal::getMessage() const noexcept {
  return {message, message_size};
};



void Crypt::ELGamal::setCipher(const void* data, size_t size) noexcept {
  if(data == nullptr || size == 0) {
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



std::pair<const void*, size_t> Crypt::ELGamal::getCipher() const noexcept {
  return {cipher, cipher_size};
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
void Crypt::ELGamal::crypt() noexcept {
  if(!p_is_prime || !g_is_valid || !x_is_valid) return;
  if(message == nullptr || message_size == 0) return;

  delete[] static_cast<unsigned char*>(cipher);

  cipher = nullptr;
  cipher_size = 0;

  constexpr size_t block_size = sizeof(uint32_t);
  constexpr size_t pair_size = block_size * 2;

  auto* data = new unsigned char[message_size * pair_size];
  const auto* msg = static_cast<const unsigned char*>(message);

  for(size_t i = 0; i < message_size; ++i) {
    const size_t k = generateK();

    const uint32_t c1 = static_cast<uint32_t>(modPow(g, k, p));
    const size_t shared = modPow(y, k, p);
    const uint32_t c2 = static_cast<uint32_t>((static_cast<size_t>(msg[i]) * shared) % p);

    std::memcpy(data + i * pair_size, &c1, block_size);
    std::memcpy(data + i * pair_size + block_size, &c2, block_size);
  };

  cipher = data;
  cipher_size = message_size * pair_size;
};



void Crypt::ELGamal::encrypt() noexcept {
  if(!p_is_prime || !g_is_valid || !x_is_valid) return;
  if(cipher == nullptr || cipher_size == 0) return;

  constexpr size_t block_size = sizeof(uint32_t);
  constexpr size_t pair_size = block_size * 2;

  if(cipher_size % pair_size != 0) return;

  const size_t message_length = cipher_size / pair_size;
  const auto* encrypted = static_cast<const unsigned char*>(cipher);

  auto* data = new unsigned char[message_length];

  for(size_t i = 0; i < message_length; ++i) {
    uint32_t c1;
    uint32_t c2;

    std::memcpy(&c1, encrypted + i * pair_size, block_size);
    std::memcpy(&c2, encrypted + i * pair_size + block_size, block_size);

    const size_t shared = modPow(c1, x, p);
    const size_t inverse = modPow(shared, p - 2, p);

    data[i] = static_cast<unsigned char>((static_cast<size_t>(c2) * inverse) % p);
  };

  delete[] static_cast<unsigned char*>(message);

  message = data;
  message_size = message_length;
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
bool Crypt::ELGamal::operator==(const ELGamal& second) const noexcept {
  if(p != second.p) return false;
  if(g != second.g) return false;
  if(x != second.x) return false;
  if(y != second.y) return false;

  return true;
};



bool Crypt::ELGamal::operator!=(const ELGamal& second) const noexcept {
  return !(*this == second);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
bool Crypt::ELGamal::check_is_prime(size_t val) {
  if(val < 2) return false;
  if(val == 2 || val == 3) return true;
  if(val % 2 == 0 || val % 3 == 0) return false;

  for(size_t i = 5; i <= val / i; i += 6)
    if(val % i == 0 || val % (i + 2) == 0) return false;

  return true;
};



bool Crypt::ELGamal::generatorTest(size_t val) noexcept {
  if(!p_is_prime) return false;
  if(val <= 1 || val >= p) return false;

  const size_t group_order = p - 1;
  size_t remaining = group_order;

  for(size_t factor = 2; factor <= remaining / factor; ++factor) {
    if(remaining % factor != 0) continue;
    if(modPow(val, group_order / factor, p) == 1) return false;

    while(remaining % factor == 0) remaining /= factor;
  };

  if(remaining > 1 && modPow(val, group_order / remaining, p) == 1) return false;

  return true;
};



void Crypt::ELGamal::calculateY() noexcept {
  y = 0;

  if(!p_is_prime || !g_is_valid || !x_is_valid) return;

  y = modPow(g, x, p);
};



size_t Crypt::ELGamal::generateK() noexcept {
  static thread_local std::mt19937_64 gen(std::random_device{}());
  std::uniform_int_distribution<size_t> dist(1, p - 2);

  return dist(gen);
};



size_t Crypt::ELGamal::modPow(size_t base, size_t exp, size_t mod) noexcept {
  size_t result = 1;
  base %= mod;

  while(exp > 0) {
    if(exp & 1) result = (result * base) % mod;

    exp >>= 1;

    if(exp) base = (base * base) % mod;
  };

  return result;
};



//// =================== ////
//// ====== Print ====== ////
//// =================== ////
std::string& Crypt::ELGamal::str(){
  str_print = "ELGamal(p = " + std::to_string(p) + ", g = " + std::to_string(g) + ", x = " + std::to_string(x) + ", y = " + std::to_string(y) + ");";
  return str_print;
};



const char* Crypt::ELGamal::c_str(){
  return str().c_str();
};
