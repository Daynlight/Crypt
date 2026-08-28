// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <string>
#include <array>
#include <math.h>
#include <random>
#include <stdexcept>



class Elliptic{
//// ================================== ////
//// ============== Data ============== ////
//// ================================== ////
private:
  size_t modulo = 0;
  bool modulo_is_prime = false;
  size_t a = 0;
  size_t b = 0;
  bool elliptic_curve_is_valid = false;
  size_t x = 0;
  size_t y = 0;
  std::string str_print = "";
  bool point_is_valid = false;



//// ======================================= ////
//// ============== Functions ============== ////
//// ======================================= ////
//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
public:
  // core
  Elliptic() noexcept;
  Elliptic(size_t modulo, size_t a, size_t b) noexcept;
  Elliptic(size_t modulo, size_t a, size_t b, size_t x, size_t y) noexcept;
  ~Elliptic() noexcept;

  // copy
  Elliptic(const Elliptic& second) noexcept;
  Elliptic& operator=(const Elliptic& second) noexcept;
  
  // move
  Elliptic(Elliptic&& second) noexcept;
  Elliptic& operator=(Elliptic&& second) noexcept;

//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
  constexpr size_t getModulo() const noexcept;
  void setModulo(size_t modulo) noexcept;
  constexpr std::array<size_t, 2> getEllipticParams() const noexcept;
  constexpr void setEllipticParams(size_t a, size_t b) noexcept;
  constexpr void setEllipticParams(std::array<size_t, 2> params) noexcept;
  constexpr std::array<size_t, 2> getPoint() const noexcept;
  constexpr void setPoint(size_t x, size_t y) noexcept;
  constexpr void setPoint(std::array<size_t, 2> point) noexcept;
  constexpr bool moduloIsPrime() const noexcept;
  constexpr bool ellipticCurveIsValid() const noexcept;
  constexpr bool pointIsValid() const noexcept;
  
//// ======================== ////
//// ====== Arithmetic ====== ////
//// ======================== ////
public:
  Elliptic add(const Elliptic& second);
  Elliptic minus(const Elliptic& second);
  Elliptic mult(size_t multiplier);
  Elliptic inverse() const;

  Elliptic operator+(const Elliptic& second);
  Elliptic& operator+=(const Elliptic& second);
  Elliptic operator-(const Elliptic& second);
  Elliptic& operator-=(const Elliptic& second);
  Elliptic operator*(size_t multiplier);
  Elliptic& operator*=(size_t multiplier);
    
//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
  bool operator==(const Elliptic& second) const noexcept;
  bool operator!=(const Elliptic& second) const noexcept;

//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
private:
  constexpr bool check_point_is_valid() noexcept;
  constexpr bool check_elliptic_curve_is_valid() noexcept;
  bool check_modulo_is_prime();
  constexpr size_t calculate_lambda(const Elliptic& second);
  constexpr size_t calculate_inv(size_t val);

//// =================== ////
//// ====== Print ====== ////
//// =================== ////
public:
  std::string& str();
  const char* c_str();
};
