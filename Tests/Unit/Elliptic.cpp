// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>
#include <array>

#define private public
#define protected public

#include <Crypt/Elliptic/Elliptic.h>

#undef private
#undef protected



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(EllipticConstructors, HandlesInitialization){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_EQ(elliptic.getModulo(), 17);
  EXPECT_EQ(elliptic.getEllipticParams()[0], 2);
  EXPECT_EQ(elliptic.getEllipticParams()[1], 2);
  EXPECT_EQ(elliptic.getPoint()[0], 5);
  EXPECT_EQ(elliptic.getPoint()[1], 1);

  EXPECT_TRUE(elliptic.moduloIsPrime());
  EXPECT_TRUE(elliptic.ellipticCurveIsValid());
  EXPECT_TRUE(elliptic.pointIsValid());
};

TEST(EllipticConstructors, HandlesEllipticParams){
  Crypt::Elliptic elliptic(17, 2, 2);

  EXPECT_EQ(elliptic.getModulo(), 17);
  EXPECT_EQ(elliptic.getEllipticParams()[0], 2);
  EXPECT_EQ(elliptic.getEllipticParams()[1], 2);

  EXPECT_TRUE(elliptic.moduloIsPrime());
  EXPECT_TRUE(elliptic.ellipticCurveIsValid());
};

//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(EllipticCopy, HandlesCopyConstructor){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
  Crypt::Elliptic copy(elliptic);

  EXPECT_EQ(copy.getModulo(), elliptic.getModulo());
  EXPECT_EQ(copy.getEllipticParams(), elliptic.getEllipticParams());
  EXPECT_EQ(copy.getPoint(), elliptic.getPoint());

  EXPECT_EQ(copy.moduloIsPrime(), elliptic.moduloIsPrime());
  EXPECT_EQ(copy.ellipticCurveIsValid(), elliptic.ellipticCurveIsValid());
  EXPECT_EQ(copy.pointIsValid(), elliptic.pointIsValid());
};

TEST(EllipticCopy, HandlesCopyAssignment){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
  Crypt::Elliptic copy(19, 1, 1, 0, 1);

  copy = elliptic;

  EXPECT_EQ(copy.getModulo(), elliptic.getModulo());
  EXPECT_EQ(copy.getEllipticParams(), elliptic.getEllipticParams());
  EXPECT_EQ(copy.getPoint(), elliptic.getPoint());

  EXPECT_EQ(copy.moduloIsPrime(), elliptic.moduloIsPrime());
  EXPECT_EQ(copy.ellipticCurveIsValid(), elliptic.ellipticCurveIsValid());
  EXPECT_EQ(copy.pointIsValid(), elliptic.pointIsValid());
};

//// ==================== ////
//// ====== Move ======== ////
//// ==================== ////
TEST(EllipticMove, HandlesMoveConstructor){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
  Crypt::Elliptic moved(std::move(elliptic));

  EXPECT_EQ(moved.getModulo(), 17);
  EXPECT_EQ(moved.getEllipticParams()[0], 2);
  EXPECT_EQ(moved.getEllipticParams()[1], 2);
  EXPECT_EQ(moved.getPoint()[0], 5);
  EXPECT_EQ(moved.getPoint()[1], 1);

  EXPECT_TRUE(moved.moduloIsPrime());
  EXPECT_TRUE(moved.ellipticCurveIsValid());
  EXPECT_TRUE(moved.pointIsValid());
};

TEST(EllipticMove, HandlesMoveAssignment){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);
  Crypt::Elliptic moved(19, 1, 1, 0, 1);

  moved = std::move(elliptic);

  EXPECT_EQ(moved.getModulo(), 17);
  EXPECT_EQ(moved.getEllipticParams()[0], 2);
  EXPECT_EQ(moved.getEllipticParams()[1], 2);
  EXPECT_EQ(moved.getPoint()[0], 5);
  EXPECT_EQ(moved.getPoint()[1], 1);

  EXPECT_TRUE(moved.moduloIsPrime());
  EXPECT_TRUE(moved.ellipticCurveIsValid());
  EXPECT_TRUE(moved.pointIsValid());
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(EllipticGettersSetters, HandlesModulo){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  elliptic.setModulo(19);

  EXPECT_EQ(elliptic.getModulo(), 19);
  EXPECT_TRUE(elliptic.moduloIsPrime());
};

TEST(EllipticGettersSetters, HandlesEllipticParams){
  Crypt::Elliptic elliptic(17, 1, 1, 5, 1);

  elliptic.setEllipticParams(2, 2);

  std::array<size_t, 2> params = elliptic.getEllipticParams();

  EXPECT_EQ(params[0], 2);
  EXPECT_EQ(params[1], 2);
  EXPECT_TRUE(elliptic.ellipticCurveIsValid());
};

TEST(EllipticGettersSetters, HandlesEllipticParamsArray){
  Crypt::Elliptic elliptic(17, 1, 1, 5, 1);

  std::array<size_t, 2> params = {2, 2};
  elliptic.setEllipticParams(params);

  EXPECT_EQ(elliptic.getEllipticParams()[0], 2);
  EXPECT_EQ(elliptic.getEllipticParams()[1], 2);
  EXPECT_TRUE(elliptic.ellipticCurveIsValid());
};

TEST(EllipticGettersSetters, HandlesPoint){
  Crypt::Elliptic elliptic(17, 2, 2);

  elliptic.setPoint(5, 1);

  std::array<size_t, 2> point = elliptic.getPoint();

  EXPECT_EQ(point[0], 5);
  EXPECT_EQ(point[1], 1);
  EXPECT_TRUE(elliptic.pointIsValid());
};

TEST(EllipticGettersSetters, HandlesPointArray){
  Crypt::Elliptic elliptic(17, 2, 2);

  std::array<size_t, 2> point = {5, 1};
  elliptic.setPoint(point);

  EXPECT_EQ(elliptic.getPoint()[0], 5);
  EXPECT_EQ(elliptic.getPoint()[1], 1);
  EXPECT_TRUE(elliptic.pointIsValid());
};

TEST(EllipticGettersSetters, HandlesInvalidModulo){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  elliptic.setModulo(15);

  EXPECT_EQ(elliptic.getModulo(), 15);
  EXPECT_FALSE(elliptic.moduloIsPrime());
};

TEST(EllipticGettersSetters, HandlesInvalidEllipticParams){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  elliptic.setEllipticParams(0, 0);

  EXPECT_FALSE(elliptic.ellipticCurveIsValid());
};

TEST(EllipticGettersSetters, HandlesInvalidPoint){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  elliptic.setPoint(1, 1);

  EXPECT_FALSE(elliptic.pointIsValid());
};



//// ======================== ////
//// ====== Arithmetic ====== ////
//// ======================== ////
TEST(EllipticArithmetic, HandlesAdd){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic.add(elliptic);

  EXPECT_EQ(result.getPoint()[0], 6);
  EXPECT_EQ(result.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesMinus){
  Crypt::Elliptic elliptic1(17, 2, 2, 6, 3);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic1.minus(elliptic2);

  EXPECT_EQ(result.getPoint()[0], 5);
  EXPECT_EQ(result.getPoint()[1], 1);
};

TEST(EllipticArithmetic, HandlesMult){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic.mult(2);

  EXPECT_EQ(result.getPoint()[0], 6);
  EXPECT_EQ(result.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesInverse){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic.inverse();

  EXPECT_EQ(result.getPoint()[0], 5);
  EXPECT_EQ(result.getPoint()[1], 16);
};

TEST(EllipticArithmetic, HandlesAdditionOperator){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic1 + elliptic2;

  EXPECT_EQ(result.getPoint()[0], 6);
  EXPECT_EQ(result.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesAdditionAssignmentOperator){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  elliptic1 += elliptic2;

  EXPECT_EQ(elliptic1.getPoint()[0], 6);
  EXPECT_EQ(elliptic1.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesSubtractionOperator){
  Crypt::Elliptic elliptic1(17, 2, 2, 6, 3);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic1 - elliptic2;

  EXPECT_EQ(result.getPoint()[0], 5);
  EXPECT_EQ(result.getPoint()[1], 1);
};

TEST(EllipticArithmetic, HandlesSubtractionAssignmentOperator){
  Crypt::Elliptic elliptic1(17, 2, 2, 6, 3);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  elliptic1 -= elliptic2;

  EXPECT_EQ(elliptic1.getPoint()[0], 5);
  EXPECT_EQ(elliptic1.getPoint()[1], 1);
};

TEST(EllipticArithmetic, HandlesMultiplicationOperator){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  Crypt::Elliptic result = elliptic * 2;

  EXPECT_EQ(result.getPoint()[0], 6);
  EXPECT_EQ(result.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesMultiplicationAssignmentOperator){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  elliptic *= 2;

  EXPECT_EQ(elliptic.getPoint()[0], 6);
  EXPECT_EQ(elliptic.getPoint()[1], 3);
};

TEST(EllipticArithmetic, HandlesKeyExchange){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  elliptic1 *= 2;
  elliptic2 *= 3;

  EXPECT_TRUE(elliptic1 != elliptic2);

  elliptic1 *= 3;
  elliptic2 *= 2;

  EXPECT_TRUE(elliptic1 == elliptic2);
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
TEST(EllipticLogic, HandlesEquality){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  EXPECT_TRUE(elliptic1 == elliptic2);
};

TEST(EllipticLogic, HandlesInequality){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 6, 3);

  EXPECT_TRUE(elliptic1 != elliptic2);
};

TEST(EllipticLogic, HandlesDifferentModulo){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(19, 2, 2, 5, 1);

  EXPECT_TRUE(elliptic1 != elliptic2);
};

TEST(EllipticLogic, HandlesDifferentEllipticParams){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 1, 2, 5, 1);

  EXPECT_TRUE(elliptic1 != elliptic2);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
TEST(EllipticHelpers, HandlesPointValidation){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_TRUE(elliptic.check_point_is_valid());

  elliptic.x = 1;
  elliptic.y = 1;

  EXPECT_FALSE(elliptic.check_point_is_valid());
};

TEST(EllipticHelpers, HandlesEllipticCurveValidation){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_TRUE(elliptic.check_elliptic_curve_is_valid());

  elliptic.a = 0;
  elliptic.b = 0;

  EXPECT_FALSE(elliptic.check_elliptic_curve_is_valid());
};

TEST(EllipticHelpers, HandlesModuloPrimeValidation){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_TRUE(elliptic.check_modulo_is_prime());

  elliptic.modulo = 15;

  EXPECT_FALSE(elliptic.check_modulo_is_prime());
};

TEST(EllipticHelpers, HandlesCalculateInverse){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_EQ(elliptic.calculate_inv(2), 9);
};

TEST(EllipticHelpers, HandlesCalculateLambda){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_EQ(elliptic.calculate_lambda(elliptic), 13);
};

TEST(EllipticHelpers, HandlesCalculateLambdaDivisionByZero){
  Crypt::Elliptic elliptic1(17, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 16);

  EXPECT_THROW(elliptic1.calculate_lambda(elliptic2), std::runtime_error);
};

TEST(EllipticHelpers, HandlesAddInvalidModulo){
  Crypt::Elliptic elliptic1(15, 2, 2, 5, 1);
  Crypt::Elliptic elliptic2(15, 2, 2, 5, 1);

  EXPECT_THROW(elliptic1.add(elliptic2), std::logic_error);
};

TEST(EllipticHelpers, HandlesAddInvalidCurve){
  Crypt::Elliptic elliptic1(17, 0, 0, 0, 0);
  Crypt::Elliptic elliptic2(17, 0, 0, 0, 0);

  EXPECT_THROW(elliptic1.add(elliptic2), std::logic_error);
};

TEST(EllipticHelpers, HandlesAddInvalidPoint){
  Crypt::Elliptic elliptic1(17, 2, 2, 1, 1);
  Crypt::Elliptic elliptic2(17, 2, 2, 5, 1);

  EXPECT_THROW(elliptic1.add(elliptic2), std::logic_error);
};



//// =================== ////
//// ====== Print ====== ////
//// =================== ////
TEST(EllipticPrint, HandlesString){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_EQ(elliptic.str(), "Elliptic(modulo = 17, a = 2, b = 2, x = 5, y = 1)");
};

TEST(EllipticPrint, HandlesCString){
  Crypt::Elliptic elliptic(17, 2, 2, 5, 1);

  EXPECT_STREQ(elliptic.c_str(), "Elliptic(modulo = 17, a = 2, b = 2, x = 5, y = 1)");
};
