// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"

#include <string>

#include "Elliptic/Elliptic.h"



void EllipticExample(){
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "Elliptic Examples");
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Operations on Elliptic");
  fmt::println("");

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic + elliptic;  
    fmt::println(fg(fmt::color::yellow), "{}", elliptic.c_str());
  }

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic.mult(2); 
    fmt::println(fg(fmt::color::yellow), "{}", elliptic.c_str());
  }
  
  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic *= 2; 
    fmt::println(fg(fmt::color::yellow), "{}", elliptic.c_str());
  }

  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Key Exchange on Elliptic");
  fmt::println("");
  {
    Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
    elliptic1 *= 2; 
    fmt::println(fg(fmt::color::purple), "{}", elliptic1.c_str());

    Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);
    elliptic2 *= 3; 
    fmt::println(fg(fmt::color::pink), "{}", elliptic2.c_str());

    if(elliptic1 != elliptic2)
      fmt::println(fg(fmt::color::green), "Are EQ: No");
    else  
      fmt::println(fg(fmt::color::red), "Are EQ: yes");



    elliptic1 *= 3; 
    fmt::println(fg(fmt::color::purple), "{}", elliptic1.c_str());

    elliptic2 *= 2; 
    fmt::println(fg(fmt::color::pink), "{}", elliptic2.c_str());

    if(elliptic1 == elliptic2)
      fmt::println(fg(fmt::color::green), "Are EQ: Yes");
    else  
      fmt::println(fg(fmt::color::red), "Are EQ: No");
  }
};