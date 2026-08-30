// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "Elliptic.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
// core
Crypt::Elliptic::Elliptic() noexcept {
  check_modulo_is_prime();
  check_elliptic_curve_is_valid();
  check_point_is_valid();
};



Crypt::Elliptic::Elliptic(size_t modulo, size_t a, size_t b) noexcept
  :modulo(modulo), a(a), b(b) {
  check_modulo_is_prime();
  check_elliptic_curve_is_valid();
  check_point_is_valid();
};



Crypt::Elliptic::Elliptic(size_t modulo, size_t a, size_t b, size_t x, size_t y) noexcept
  :modulo(modulo), a(a), b(b), x(x), y(y) {
  check_modulo_is_prime();
  check_elliptic_curve_is_valid();
  check_point_is_valid();
};



Crypt::Elliptic::~Elliptic() noexcept {};



// copy
Crypt::Elliptic::Elliptic(const Elliptic &second) noexcept
  :modulo(second.modulo), 
  a(second.a), b(second.b), x(second.x), y(second.y), 
  modulo_is_prime(second.modulo_is_prime),
  elliptic_curve_is_valid(second.elliptic_curve_is_valid),
  point_is_valid(second.point_is_valid) {};



Crypt::Elliptic& Crypt::Elliptic::operator=(const Elliptic& second) noexcept {
  if(this == &second) return *this;
  
  x = second.x;
  y = second.y;
  a = second.a;
  b = second.b;
  modulo = second.modulo;
  modulo_is_prime = second.modulo_is_prime;
  elliptic_curve_is_valid = second.elliptic_curve_is_valid;
  point_is_valid = second.point_is_valid;

  return *this;
};



// move
Crypt::Elliptic::Elliptic(Elliptic &&second) noexcept
  :modulo(std::move(second.modulo)), 
  a(std::move(second.a)), b(std::move(second.b)), 
  x(std::move(second.x)), y(std::move(second.y)),
  modulo_is_prime(std::move(second.modulo_is_prime)),
  elliptic_curve_is_valid(std::move(second.elliptic_curve_is_valid)),
  point_is_valid(std::move(second.point_is_valid)) {};



Crypt::Elliptic& Crypt::Elliptic::operator=(Elliptic&& second) noexcept {
  if(this == &second) return *this;

  x = std::move(second.x);
  y = std::move(second.y);
  a = std::move(second.a);
  b = std::move(second.b);
  modulo = std::move(second.modulo);
  modulo_is_prime = std::move(second.modulo_is_prime);
  elliptic_curve_is_valid = std::move(second.elliptic_curve_is_valid);
  point_is_valid = std::move(second.point_is_valid);

  return *this;
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
size_t Crypt::Elliptic::getModulo() const noexcept {
  return modulo;
};



void Crypt::Elliptic::setModulo(size_t modulo) noexcept {
  this->modulo = modulo;
  check_modulo_is_prime();
};



std::array<size_t, 2> Crypt::Elliptic::getEllipticParams() const noexcept {
  return {a, b};
};



void Crypt::Elliptic::setEllipticParams(size_t a, size_t b) noexcept {
  this->a = a;
  this->b = b;
  check_elliptic_curve_is_valid();
};



void Crypt::Elliptic::setEllipticParams(std::array<size_t, 2> params) noexcept {
  this->a = params[0];
  this->b = params[1];
  check_elliptic_curve_is_valid();
};



std::array<size_t, 2> Crypt::Elliptic::getPoint() const noexcept {
  return {x, y};
};



void Crypt::Elliptic::setPoint(size_t x, size_t y) noexcept {
  this->x = x;
  this->y = y;
  check_point_is_valid();
};



void Crypt::Elliptic::setPoint(std::array<size_t, 2> point) noexcept {
  this->x = point[0];
  this->y = point[1];
  check_point_is_valid();
};



bool Crypt::Elliptic::moduloIsPrime() const noexcept {
  return modulo_is_prime;
};



bool Crypt::Elliptic::ellipticCurveIsValid() const noexcept {
  return elliptic_curve_is_valid;
};



bool Crypt::Elliptic::pointIsValid() const noexcept {
  return point_is_valid;
};



//// ======================== ////
//// ====== Arithmetic ====== ////
//// ======================== ////
Crypt::Elliptic Crypt::Elliptic::add(const Elliptic& second){
  if(!modulo_is_prime) throw std::logic_error("add(), Modulo is not Prime");
  if(!elliptic_curve_is_valid) throw std::logic_error("add(), Elliptic curve is not valid");
  if(!point_is_valid) throw std::logic_error("add(), Point is not valid");

  Elliptic result = *this;
  
  if(y == 0) result = second;
  else if(second.y == 0) result = *this;
  else {
    size_t lambda = calculate_lambda(second);
    size_t new_x = (lambda*lambda + modulo - x + modulo - second.x) % modulo;
    size_t new_y = (lambda*(x + modulo - new_x) + modulo - y) % modulo;

    result.x = new_x;
    result.y = new_y;
    result.check_point_is_valid();
  }

  return result;
};



Crypt::Elliptic Crypt::Elliptic::minus(const Elliptic& second){
  Elliptic second_inverse = second.inverse();

  return add(second_inverse);
};



Crypt::Elliptic Crypt::Elliptic::mult(size_t multiplier){
  Elliptic result = *this;
  for(int i = 1; i < multiplier; i++) result = result.add(*this);
  result.check_point_is_valid();
  return result;
};



Crypt::Elliptic Crypt::Elliptic::inverse() const {
  Elliptic result = *this;
  if (result.y != 0) result.y = modulo - result.y;
  return result;
};



Crypt::Elliptic Crypt::Elliptic::operator+(const Elliptic& second){
  return add(second);
};



Crypt::Elliptic& Crypt::Elliptic::operator+=(const Elliptic& second){
  *this = add(second);
  return *this;
};



Crypt::Elliptic Crypt::Elliptic::operator-(const Elliptic& second){
  return minus(second);
};



Crypt::Elliptic& Crypt::Elliptic::operator-=(const Elliptic& second){
  *this = minus(second);
  return *this;
};



Crypt::Elliptic Crypt::Elliptic::operator*(size_t multiplier){
  return mult(multiplier);
};



Crypt::Elliptic& Crypt::Elliptic::operator*=(size_t multiplier){
  *this = mult(multiplier);
  return *this;
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
bool Crypt::Elliptic::operator==(const Elliptic& second) const noexcept {
  if(modulo != second.modulo) return false;
  if(a != second.a) return false;
  if(b != second.b) return false;
  if(x != second.x) return false;
  if(y != second.y) return false;

  return true;
};



bool Crypt::Elliptic::operator!=(const Elliptic& second) const noexcept {
  return !(*this == second);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
bool Crypt::Elliptic::check_point_is_valid() noexcept {
  point_is_valid = ((y*y) % modulo) == (x*x*x + a*x + b) % modulo;
  return point_is_valid;
};



bool Crypt::Elliptic::check_elliptic_curve_is_valid() noexcept {
  elliptic_curve_is_valid = (4*a*a*a + 27*b*b) % modulo != 0;
  return elliptic_curve_is_valid;
};



bool Crypt::Elliptic::check_modulo_is_prime() {
  if(modulo == 2 || modulo == 3) {
    modulo_is_prime = true;
    return modulo_is_prime;
  };
  if(modulo < 5) {
    modulo_is_prime = false;
    return modulo_is_prime;
  };
  
  std::mt19937 gen(std::random_device{}()); 
  std::uniform_int_distribution<size_t> dist(2, modulo - 2);
  size_t test = dist(gen);
  size_t inc_test = test;
  for(int i = 1; i < modulo - 1; i++)
    inc_test = (inc_test * test) % modulo;
  if(inc_test % modulo != 1) {
    modulo_is_prime = false;
    return modulo_is_prime;
  };

  int sq = sqrt(modulo);

  for(int i = 2; i <= sq; i++)
    if(modulo % i == 0) {
      modulo_is_prime = false;
      return modulo_is_prime;
    };

  modulo_is_prime = true;
  return modulo_is_prime;
};



size_t Crypt::Elliptic::calculate_lambda(const Elliptic& second){
  size_t lambda_top = 0;
  size_t lambda_bot = 0;

  if(x == second.x && y == second.y) {
    lambda_top = (3*x*x + a) % modulo;
    lambda_bot = (2*y) % modulo;
  }
  else {
    lambda_top = (y + modulo - second.y) % modulo;
    lambda_bot =  (x + modulo - second.x) % modulo;
  };

  if(lambda_bot == 0) throw std::runtime_error("calculate_lambda cant divide by 0, y is 0");

  size_t lambda_bot_inv = calculate_inv(lambda_bot);
  size_t lambda = (lambda_top * lambda_bot_inv) % modulo;

  return lambda;
};



size_t Crypt::Elliptic::calculate_inv(size_t val){
  size_t lam_bot_inv = 1;
  for(int i = 0; i < modulo - 2; i ++){
    lam_bot_inv *= val;
    lam_bot_inv = lam_bot_inv % modulo;
  };

  return lam_bot_inv;
};



//// =================== ////
//// ====== Print ====== ////
//// =================== ////
std::string& Crypt::Elliptic::str(){
  str_print = "Elliptic(modulo = "+ std::to_string(modulo) +", a = "+ std::to_string(a) +", b = "+ std::to_string(b) +", x = "+ std::to_string(x) +", y = "+ std::to_string(y) +")";
  return str_print;
};



const char* Crypt::Elliptic::c_str(){
  return str().c_str();
};
