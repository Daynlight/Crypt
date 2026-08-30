// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>

#define private public
#define protected public

#include <Crypt/Elliptic/Elliptic.h>

#undef private
#undef protected



TEST(EllipticOperationsExchange, HandlesInitialization){
  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic + elliptic;
    std::array<size_t, 2> point = elliptic.getPoint();
    EXPECT_EQ(point[0], 6);
    EXPECT_EQ(point[1], 3);
  }

  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic.mult(2); 
    std::array<size_t, 2> point = elliptic.getPoint();
    EXPECT_EQ(point[0], 6);
    EXPECT_EQ(point[1], 3);
  }
  
  {
    Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic *= 2; 
    std::array<size_t, 2> point = elliptic.getPoint();
    EXPECT_EQ(point[0], 6);
    EXPECT_EQ(point[1], 3);
  }
};

TEST(EllipticKeyExchange, HandlesInitialization){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  elliptic1 *= 2;

  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);
  elliptic2 *= 3;

  EXPECT_TRUE(elliptic1 != elliptic2) << "elliptic should be different";

  elliptic1 *= 3;

  elliptic2 *= 2;

  EXPECT_TRUE(elliptic1 == elliptic2) << "elliptic should be the same";
};
