// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>

#define private public
#define protected public

#include <Crypt/ElGamal/ElGamal.h>

#undef private
#undef protected



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(ELGamalConstructors, HandlesInitialization){
  Crypt::ELGamal elgamal;

  EXPECT_EQ(elgamal.p, 1);
  EXPECT_EQ(elgamal.g, 0);
  EXPECT_EQ(elgamal.x, 0);
  EXPECT_EQ(elgamal.y, 0);

  EXPECT_FALSE(elgamal.p_is_prime);
  EXPECT_FALSE(elgamal.g_is_valid);
  EXPECT_FALSE(elgamal.x_is_valid);

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.message_size, 0);

  EXPECT_EQ(elgamal.cipher, nullptr);
  EXPECT_EQ(elgamal.cipher_size, 0);
};

TEST(ELGamalConstructors, HandlesKeyInitialization){
  Crypt::ELGamal elgamal(467, 2, 127);

  EXPECT_EQ(elgamal.p, 467);
  EXPECT_EQ(elgamal.g, 2);
  EXPECT_EQ(elgamal.x, 127);
  EXPECT_EQ(elgamal.y, 132);

  EXPECT_TRUE(elgamal.p_is_prime);
  EXPECT_TRUE(elgamal.g_is_valid);
  EXPECT_TRUE(elgamal.x_is_valid);
};

//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(ELGamalCopy, HandlesCopyConstructor){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  Crypt::ELGamal copy(elgamal);

  EXPECT_EQ(copy.p, elgamal.p);
  EXPECT_EQ(copy.g, elgamal.g);
  EXPECT_EQ(copy.x, elgamal.x);
  EXPECT_EQ(copy.y, elgamal.y);

  EXPECT_EQ(copy.p_is_prime, elgamal.p_is_prime);
  EXPECT_EQ(copy.g_is_valid, elgamal.g_is_valid);
  EXPECT_EQ(copy.x_is_valid, elgamal.x_is_valid);

  EXPECT_NE(copy.message, elgamal.message);
  EXPECT_EQ(copy.message_size, elgamal.message_size);
  EXPECT_EQ(std::memcmp(copy.message, elgamal.message, elgamal.message_size), 0);

  EXPECT_NE(copy.cipher, elgamal.cipher);
  EXPECT_EQ(copy.cipher_size, elgamal.cipher_size);
  EXPECT_EQ(std::memcmp(copy.cipher, elgamal.cipher, elgamal.cipher_size), 0);
};

TEST(ELGamalCopy, HandlesCopyAssignment){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  Crypt::ELGamal copy;

  copy = elgamal;

  EXPECT_EQ(copy.p, elgamal.p);
  EXPECT_EQ(copy.g, elgamal.g);
  EXPECT_EQ(copy.x, elgamal.x);
  EXPECT_EQ(copy.y, elgamal.y);

  EXPECT_EQ(copy.p_is_prime, elgamal.p_is_prime);
  EXPECT_EQ(copy.g_is_valid, elgamal.g_is_valid);
  EXPECT_EQ(copy.x_is_valid, elgamal.x_is_valid);

  EXPECT_NE(copy.message, elgamal.message);
  EXPECT_EQ(copy.message_size, elgamal.message_size);
  EXPECT_EQ(std::memcmp(copy.message, elgamal.message, elgamal.message_size), 0);

  EXPECT_NE(copy.cipher, elgamal.cipher);
  EXPECT_EQ(copy.cipher_size, elgamal.cipher_size);
  EXPECT_EQ(std::memcmp(copy.cipher, elgamal.cipher, elgamal.cipher_size), 0);
};

TEST(ELGamalCopy, HandlesDeepCopy){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  Crypt::ELGamal copy(elgamal);

  static_cast<unsigned char*>(elgamal.message)[0] ^= 0xFF;
  static_cast<unsigned char*>(elgamal.cipher)[0] ^= 0xFF;

  EXPECT_NE(static_cast<unsigned char*>(copy.message)[0], static_cast<unsigned char*>(elgamal.message)[0]);
  EXPECT_NE(static_cast<unsigned char*>(copy.cipher)[0], static_cast<unsigned char*>(elgamal.cipher)[0]);
};

//// ==================== ////
//// ====== Move ======== ////
//// ==================== ////
TEST(ELGamalMove, HandlesMoveConstructor){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  void* message_ptr = elgamal.message;
  void* cipher_ptr = elgamal.cipher;

  size_t message_size = elgamal.message_size;
  size_t cipher_size = elgamal.cipher_size;

  Crypt::ELGamal moved(std::move(elgamal));

  EXPECT_EQ(moved.message, message_ptr);
  EXPECT_EQ(moved.cipher, cipher_ptr);

  EXPECT_EQ(moved.message_size, message_size);
  EXPECT_EQ(moved.cipher_size, cipher_size);

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.cipher, nullptr);

  EXPECT_EQ(elgamal.message_size, 0);
  EXPECT_EQ(elgamal.cipher_size, 0);
};

TEST(ELGamalMove, HandlesMoveAssignment){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  void* message_ptr = elgamal.message;
  void* cipher_ptr = elgamal.cipher;

  size_t message_size = elgamal.message_size;
  size_t cipher_size = elgamal.cipher_size;

  Crypt::ELGamal moved;

  moved = std::move(elgamal);

  EXPECT_EQ(moved.message, message_ptr);
  EXPECT_EQ(moved.cipher, cipher_ptr);

  EXPECT_EQ(moved.message_size, message_size);
  EXPECT_EQ(moved.cipher_size, cipher_size);

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.cipher, nullptr);

  EXPECT_EQ(elgamal.message_size, 0);
  EXPECT_EQ(elgamal.cipher_size, 0);
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(ELGamalGettersSetters, HandlesP){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);

  EXPECT_EQ(elgamal.getP(), 467);
  EXPECT_TRUE(elgamal.pIsPrime());
};

TEST(ELGamalGettersSetters, HandlesInvalidP){
  Crypt::ELGamal elgamal;

  elgamal.setP(100);

  EXPECT_EQ(elgamal.getP(), 100);
  EXPECT_FALSE(elgamal.pIsPrime());
};

TEST(ELGamalGettersSetters, HandlesG){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);

  EXPECT_EQ(elgamal.getG(), 2);
  EXPECT_TRUE(elgamal.gIsValid());
};

TEST(ELGamalGettersSetters, HandlesInvalidG){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(4);

  EXPECT_EQ(elgamal.getG(), 0);
  EXPECT_FALSE(elgamal.gIsValid());
};

TEST(ELGamalGettersSetters, HandlesX){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  EXPECT_EQ(elgamal.getX(), 127);
  EXPECT_TRUE(elgamal.xIsValid());
};

TEST(ELGamalGettersSetters, HandlesInvalidX){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(466);

  EXPECT_EQ(elgamal.getX(), 0);
  EXPECT_FALSE(elgamal.xIsValid());
};

TEST(ELGamalGettersSetters, HandlesY){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  EXPECT_EQ(elgamal.getY(), 132);
};

TEST(ELGamalGettersSetters, HandlesMessage){
  Crypt::ELGamal elgamal;

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());

  std::pair<const void*, size_t> result = elgamal.getMessage();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, message.size());
  EXPECT_EQ(std::memcmp(result.first, message.data(), message.size()), 0);
};

TEST(ELGamalGettersSetters, HandlesMessageDeepCopy){
  Crypt::ELGamal elgamal;

  std::string message = "Hello World";
  std::string original = message;

  elgamal.setMessage(message.data(), message.size());

  message[0] = 'X';

  EXPECT_EQ(std::memcmp(elgamal.message, original.data(), original.size()), 0);
};

TEST(ELGamalGettersSetters, HandlesMessageReplacement){
  Crypt::ELGamal elgamal;

  std::string first = "First Message";
  std::string second = "Second Message";

  elgamal.setMessage(first.data(), first.size());
  elgamal.setMessage(second.data(), second.size());

  EXPECT_EQ(elgamal.message_size, second.size());
  EXPECT_EQ(std::memcmp(elgamal.message, second.data(), second.size()), 0);
};

TEST(ELGamalGettersSetters, HandlesEmptyMessage){
  Crypt::ELGamal elgamal;

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.setMessage(nullptr, 0);

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.message_size, 0);
};

TEST(ELGamalGettersSetters, HandlesCipher){
  Crypt::ELGamal elgamal;

  std::array<unsigned char, 8> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
  };

  elgamal.setCipher(cipher.data(), cipher.size());

  std::pair<const void*, size_t> result = elgamal.getCipher();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, cipher.size());
  EXPECT_EQ(std::memcmp(result.first, cipher.data(), cipher.size()), 0);
};

TEST(ELGamalGettersSetters, HandlesCipherDeepCopy){
  Crypt::ELGamal elgamal;

  std::array<unsigned char, 8> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
  };

  std::array<unsigned char, 8> original = cipher;

  elgamal.setCipher(cipher.data(), cipher.size());

  cipher[0] = 0xFF;

  EXPECT_EQ(std::memcmp(elgamal.cipher, original.data(), original.size()), 0);
};

TEST(ELGamalGettersSetters, HandlesEmptyCipher){
  Crypt::ELGamal elgamal;

  std::array<unsigned char, 8> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
  };

  elgamal.setCipher(cipher.data(), cipher.size());
  elgamal.setCipher(nullptr, 0);

  EXPECT_EQ(elgamal.cipher, nullptr);
  EXPECT_EQ(elgamal.cipher_size, 0);
};



//// ====================== ////
//// ====== Key Data ====== ////
//// ====================== ////
TEST(ELGamalData, HandlesPublicKey){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  EXPECT_EQ(elgamal.y, 132);
};

TEST(ELGamalData, HandlesPReplacement){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  EXPECT_TRUE(elgamal.gIsValid());
  EXPECT_TRUE(elgamal.xIsValid());

  elgamal.setP(100);

  EXPECT_FALSE(elgamal.pIsPrime());
  EXPECT_FALSE(elgamal.gIsValid());
  EXPECT_FALSE(elgamal.xIsValid());

  EXPECT_EQ(elgamal.g, 0);
  EXPECT_EQ(elgamal.x, 0);
  EXPECT_EQ(elgamal.y, 0);
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
TEST(ELGamalCrypt, HandlesMessage){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  ASSERT_NE(elgamal.cipher, nullptr);
  EXPECT_EQ(elgamal.cipher_size, message.size() * sizeof(uint32_t) * 2);
};

TEST(ELGamalCrypt, CipherDiffersFromMessage){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  ASSERT_NE(elgamal.cipher, nullptr);
  EXPECT_NE(elgamal.cipher_size, message.size());
};

TEST(ELGamalCrypt, HandlesEmptyMessage){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  elgamal.crypt();

  EXPECT_EQ(elgamal.cipher, nullptr);
  EXPECT_EQ(elgamal.cipher_size, 0);
};

TEST(ELGamalCrypt, HandlesBinaryData){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03,
    0x10, 0x20, 0x42, 0x7F,
    0x80, 0xAA, 0xFE, 0xFF
  };

  elgamal.setMessage(data.data(), data.size());
  elgamal.crypt();

  ASSERT_NE(elgamal.cipher, nullptr);
  EXPECT_EQ(elgamal.cipher_size, data.size() * sizeof(uint32_t) * 2);
};

TEST(ELGamalCrypt, ProducesDifferentCipher){
  Crypt::ELGamal elgamal1;
  Crypt::ELGamal elgamal2;

  elgamal1.setP(467);
  elgamal1.setG(2);
  elgamal1.setX(127);

  elgamal2.setP(467);
  elgamal2.setG(2);
  elgamal2.setX(127);

  std::string message = "Hello World";

  elgamal1.setMessage(message.data(), message.size());
  elgamal2.setMessage(message.data(), message.size());

  elgamal1.crypt();
  elgamal2.crypt();

  ASSERT_NE(elgamal1.cipher, nullptr);
  ASSERT_NE(elgamal2.cipher, nullptr);

  EXPECT_NE(std::memcmp(elgamal1.cipher, elgamal2.cipher, elgamal1.cipher_size), 0);
};

//// ===================== ////
//// ====== Encrypt ====== ////
//// ===================== ////
TEST(ELGamalEncrypt, HandlesMessage){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());

  elgamal.crypt();
  elgamal.encrypt();

  std::pair<const void*, size_t> result = elgamal.getMessage();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, message.size());

  std::string recreated(static_cast<const char*>(result.first), result.second);

  EXPECT_EQ(message, recreated);
};

TEST(ELGamalEncrypt, HandlesSeparateObjects){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";

  elgamal.setMessage(message.data(), message.size());
  elgamal.crypt();

  std::pair<const void*, size_t> cipher = elgamal.getCipher();

  Crypt::ELGamal elgamal2;

  elgamal2.setP(467);
  elgamal2.setG(2);
  elgamal2.setX(127);

  elgamal2.setCipher(cipher.first, cipher.second);
  elgamal2.encrypt();

  std::pair<const void*, size_t> result = elgamal2.getMessage();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, message.size());

  std::string recreated(static_cast<const char*>(result.first), result.second);

  EXPECT_EQ(message, recreated);
};

TEST(ELGamalEncrypt, HandlesBinaryData){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03,
    0x10, 0x20, 0x42, 0x7F,
    0x80, 0xAA, 0xFE, 0xFF
  };

  elgamal.setMessage(data.data(), data.size());

  elgamal.crypt();
  elgamal.encrypt();

  ASSERT_NE(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.message_size, data.size());
  EXPECT_EQ(std::memcmp(elgamal.message, data.data(), data.size()), 0);
};

TEST(ELGamalEncrypt, HandlesEmptyCipher){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  elgamal.encrypt();

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.message_size, 0);
};

TEST(ELGamalEncrypt, HandlesInvalidCipherSize){
  Crypt::ELGamal elgamal;

  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::array<unsigned char, 7> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07
  };

  elgamal.setCipher(cipher.data(), cipher.size());
  elgamal.encrypt();

  EXPECT_EQ(elgamal.message, nullptr);
  EXPECT_EQ(elgamal.message_size, 0);
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
TEST(ELGamalLogic, HandlesEquality){
  Crypt::ELGamal elgamal1;
  Crypt::ELGamal elgamal2;

  elgamal1.setP(467);
  elgamal1.setG(2);
  elgamal1.setX(127);

  elgamal2.setP(467);
  elgamal2.setG(2);
  elgamal2.setX(127);

  EXPECT_TRUE(elgamal1 == elgamal2);
  EXPECT_FALSE(elgamal1 != elgamal2);
};

TEST(ELGamalLogic, HandlesInequality){
  Crypt::ELGamal elgamal1;
  Crypt::ELGamal elgamal2;

  elgamal1.setP(467);
  elgamal1.setG(2);
  elgamal1.setX(127);

  elgamal2.setP(467);
  elgamal2.setG(2);
  elgamal2.setX(128);

  EXPECT_FALSE(elgamal1 == elgamal2);
  EXPECT_TRUE(elgamal1 != elgamal2);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
TEST(ELGamalHelpers, HandlesPrime){
  Crypt::ELGamal elgamal;

  EXPECT_TRUE(elgamal.check_is_prime(2));
  EXPECT_TRUE(elgamal.check_is_prime(3));
  EXPECT_TRUE(elgamal.check_is_prime(5));
  EXPECT_TRUE(elgamal.check_is_prime(467));
};

TEST(ELGamalHelpers, HandlesNotPrime){
  Crypt::ELGamal elgamal;

  EXPECT_FALSE(elgamal.check_is_prime(0));
  EXPECT_FALSE(elgamal.check_is_prime(1));
  EXPECT_FALSE(elgamal.check_is_prime(4));
  EXPECT_FALSE(elgamal.check_is_prime(9));
  EXPECT_FALSE(elgamal.check_is_prime(468));
};

TEST(ELGamalHelpers, HandlesGenerator){
  Crypt::ELGamal elgamal;
  
  elgamal.setP(467);

  EXPECT_TRUE(elgamal.generatorTest(2));
  EXPECT_FALSE(elgamal.generatorTest(4));
};

TEST(ELGamalHelpers, HandlesCalculateY){
  Crypt::ELGamal elgamal;

  elgamal.p = 467;
  elgamal.g = 2;
  elgamal.x = 127;
  elgamal.p_is_prime = true;
  elgamal.g_is_valid = true;
  elgamal.x_is_valid = true;
  
  elgamal.calculateY();
  EXPECT_EQ(elgamal.y, 132);
};

TEST(ELGamalHelpers, HandlesGenerateK){
  Crypt::ELGamal elgamal;
  elgamal.setP(467);

  for(size_t i = 0; i < 100; ++i) {
    size_t k = elgamal.generateK();
    EXPECT_GE(k, 1);
    EXPECT_LE(k, 465);
  };
};

TEST(ELGamalHelpers, HandlesModPow){
  Crypt::ELGamal elgamal;
  EXPECT_EQ(elgamal.modPow(2, 10, 1000), 24);
  EXPECT_EQ(elgamal.modPow(5, 0, 7), 1);
  EXPECT_EQ(elgamal.modPow(2, 127, 467), 132);
};
