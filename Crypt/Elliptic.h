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
  size_t getModulo() const noexcept;
  void setModulo(size_t modulo) noexcept;
  std::array<size_t, 2> getEllipticParams() const noexcept;
  void setEllipticParams(size_t a, size_t b) noexcept;
  void setEllipticParams(std::array<size_t, 2> params) noexcept;
  std::array<size_t, 2> getPoint() const noexcept;
  void setPoint(size_t x, size_t y) noexcept;
  void setPoint(std::array<size_t, 2> point) noexcept;
  bool moduloIsPrime() const noexcept;
  bool ellipticCurveIsValid() const noexcept;
  bool pointIsValid() const noexcept;
  
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
  bool check_point_is_valid() noexcept;
  bool check_elliptic_curve_is_valid() noexcept;
  bool check_modulo_is_prime();
  size_t calculate_lambda(const Elliptic& second);
  size_t calculate_inv(size_t val);

//// =================== ////
//// ====== Print ====== ////
//// =================== ////
public:
  std::string& str();
  const char* c_str();
};
