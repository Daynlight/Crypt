// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"
#include <Crypt/Elliptic/Elliptic.h>



void EllipticGettersSetters(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Elliptic Setters/Getters");
  fmt::println("");

  fmt::println(fg(fmt::color::aqua), "Modulo");

  {
    Crypt::Elliptic elliptic;

    elliptic.setModulo(17);

    fmt::println(fg(fmt::color::yellow), "Set Modulo: 17");

    if(elliptic.getModulo() == 17)
      fmt::println(fg(fmt::color::green), "Recovered Modulo: {}", elliptic.getModulo());
    else
      fmt::println(fg(fmt::color::red), "Recovered Modulo: {}", elliptic.getModulo());
  }

  fmt::println(fg(fmt::color::aqua), "Elliptic Params");

  {
    Crypt::Elliptic elliptic;

    elliptic.setModulo(17);
    elliptic.setEllipticParams(2, 2);

    std::array<size_t, 2> params = elliptic.getEllipticParams();

    fmt::println(fg(fmt::color::yellow), "Set Params: a = 2, b = 2");

    if(params[0] == 2 && params[1] == 2)
      fmt::println(fg(fmt::color::green), "Recovered Params: a = {}, b = {}", params[0], params[1]);
    else
      fmt::println(fg(fmt::color::red), "Recovered Params: a = {}, b = {}", params[0], params[1]);
  }

  fmt::println(fg(fmt::color::aqua), "Point");

  {
    Crypt::Elliptic elliptic(17, 2, 2);

    elliptic.setPoint(5, 1);

    std::array<size_t, 2> point = elliptic.getPoint();

    fmt::println(fg(fmt::color::yellow), "Set Point: x = 5, y = 1");

    if(point[0] == 5 && point[1] == 1)
      fmt::println(fg(fmt::color::green), "Recovered Point: x = {}, y = {}", point[0], point[1]);
    else
      fmt::println(fg(fmt::color::red), "Recovered Point: x = {}, y = {}", point[0], point[1]);
  }
};



void EllipticOperations(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Operations on Elliptic");
  fmt::println("");

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

    fmt::println(fg(fmt::color::yellow), "Original: {}", elliptic.c_str());

    Crypt::Elliptic result = elliptic + elliptic;

    fmt::println(fg(fmt::color::green), "Point + Point: {}", result.c_str());
  }

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

    fmt::println(fg(fmt::color::yellow), "Original: {}", elliptic.c_str());

    Crypt::Elliptic result = elliptic.mult(2);

    fmt::println(fg(fmt::color::green), "Point * 2: {}", result.c_str());
  }

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

    fmt::println(fg(fmt::color::yellow), "Original: {}", elliptic.c_str());

    elliptic *= 2;

    fmt::println(fg(fmt::color::green), "Point *= 2: {}", elliptic.c_str());
  }

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

    fmt::println(fg(fmt::color::yellow), "Original: {}", elliptic.c_str());

    Crypt::Elliptic inverse = elliptic.inverse();

    fmt::println(fg(fmt::color::green), "Inverse: {}", inverse.c_str());
  }
};



void EllipticValidation(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Elliptic Validation");
  fmt::println("");

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

    fmt::println(fg(fmt::color::yellow), "{}", elliptic.c_str());

    if(elliptic.moduloIsPrime())
      fmt::println(fg(fmt::color::green), "Modulo Is Prime: Yes");
    else
      fmt::println(fg(fmt::color::red), "Modulo Is Prime: No");

    if(elliptic.ellipticCurveIsValid())
      fmt::println(fg(fmt::color::green), "Elliptic Curve Is Valid: Yes");
    else
      fmt::println(fg(fmt::color::red), "Elliptic Curve Is Valid: No");

    if(elliptic.pointIsValid())
      fmt::println(fg(fmt::color::green), "Point Is Valid: Yes");
    else
      fmt::println(fg(fmt::color::red), "Point Is Valid: No");
  }
};



void EllipticKeyExchange(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Key Exchange on Elliptic");
  fmt::println("");

  {
    Crypt::Elliptic base(17, 2, 2, 5, 1);

    size_t private_key1 = 2;
    size_t private_key2 = 3;

    Crypt::Elliptic elliptic1 = base;
    Crypt::Elliptic elliptic2 = base;

    elliptic1 *= private_key1;
    elliptic2 *= private_key2;

    fmt::println(fg(fmt::color::yellow), "Base Point: {}", base.c_str());

    fmt::println(fg(fmt::color::purple), "Private Key 1: {}", private_key1);
    fmt::println(fg(fmt::color::purple), "Public Key 1: {}", elliptic1.c_str());

    fmt::println(fg(fmt::color::pink), "Private Key 2: {}", private_key2);
    fmt::println(fg(fmt::color::pink), "Public Key 2: {}", elliptic2.c_str());

    if(elliptic1 != elliptic2)
      fmt::println(fg(fmt::color::green), "Public Keys Are Equal: No");
    else
      fmt::println(fg(fmt::color::red), "Public Keys Are Equal: Yes");

    elliptic1 *= private_key2;
    elliptic2 *= private_key1;

    fmt::println("");

    fmt::println(fg(fmt::color::purple), "Shared Key 1: {}", elliptic1.c_str());
    fmt::println(fg(fmt::color::pink), "Shared Key 2: {}", elliptic2.c_str());

    if(elliptic1 == elliptic2)
      fmt::println(fg(fmt::color::green), "Shared Keys Are Equal: Yes");
    else
      fmt::println(fg(fmt::color::red), "Shared Keys Are Equal: No");
  }
};



void EllipticExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "=====================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= Elliptic Examples =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "=====================");
  fmt::println("");

  EllipticGettersSetters();
  EllipticValidation();
  EllipticOperations();
  EllipticKeyExchange();
};