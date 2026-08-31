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

#include <Crypt/Rsa/Rsa.h>

#undef private
#undef protected



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(RsaConstructors, HandlesInitialization){
  Crypt::Rsa rsa;

  EXPECT_EQ(rsa.p, 1);
  EXPECT_EQ(rsa.q, 1);
  EXPECT_EQ(rsa.n, 1);
  EXPECT_EQ(rsa.fib_n, 0);
  EXPECT_EQ(rsa.e, 0);
  EXPECT_EQ(rsa.d, 0);

  EXPECT_FALSE(rsa.p_is_prime);
  EXPECT_FALSE(rsa.q_is_prime);
  EXPECT_FALSE(rsa.e_is_valid);

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.message_size, 0);

  EXPECT_EQ(rsa.cipher, nullptr);
  EXPECT_EQ(rsa.cipher_size, 0);
};

TEST(RsaConstructors, HandlesPQInitialization){
  Crypt::Rsa rsa(21191, 48337);

  EXPECT_EQ(rsa.p, 21191);
  EXPECT_EQ(rsa.q, 48337);

  EXPECT_TRUE(rsa.p_is_prime);
  EXPECT_TRUE(rsa.q_is_prime);

  EXPECT_EQ(rsa.n, 1024309367);
  EXPECT_EQ(rsa.fib_n, 1024239840);
};



//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(RsaCopy, HandlesCopyConstructor){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  Crypt::Rsa copy(rsa);

  EXPECT_EQ(copy.p, rsa.p);
  EXPECT_EQ(copy.q, rsa.q);
  EXPECT_EQ(copy.n, rsa.n);
  EXPECT_EQ(copy.fib_n, rsa.fib_n);
  EXPECT_EQ(copy.e, rsa.e);
  EXPECT_EQ(copy.d, rsa.d);

  EXPECT_EQ(copy.p_is_prime, rsa.p_is_prime);
  EXPECT_EQ(copy.q_is_prime, rsa.q_is_prime);
  EXPECT_EQ(copy.e_is_valid, rsa.e_is_valid);

  EXPECT_NE(copy.message, rsa.message);
  EXPECT_EQ(copy.message_size, rsa.message_size);
  EXPECT_EQ(
    std::memcmp(copy.message, rsa.message, rsa.message_size),
    0
  );

  EXPECT_NE(copy.cipher, rsa.cipher);
  EXPECT_EQ(copy.cipher_size, rsa.cipher_size);
  EXPECT_EQ(
    std::memcmp(copy.cipher, rsa.cipher, rsa.cipher_size),
    0
  );
};

TEST(RsaCopy, HandlesCopyAssignment){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  Crypt::Rsa copy;

  copy = rsa;

  EXPECT_EQ(copy.p, rsa.p);
  EXPECT_EQ(copy.q, rsa.q);
  EXPECT_EQ(copy.n, rsa.n);
  EXPECT_EQ(copy.fib_n, rsa.fib_n);
  EXPECT_EQ(copy.e, rsa.e);
  EXPECT_EQ(copy.d, rsa.d);

  EXPECT_NE(copy.message, rsa.message);
  EXPECT_EQ(copy.message_size, rsa.message_size);
  EXPECT_EQ(
    std::memcmp(copy.message, rsa.message, rsa.message_size),
    0
  );

  EXPECT_NE(copy.cipher, rsa.cipher);
  EXPECT_EQ(copy.cipher_size, rsa.cipher_size);
  EXPECT_EQ(
    std::memcmp(copy.cipher, rsa.cipher, rsa.cipher_size),
    0
  );
};

TEST(RsaCopy, HandlesDeepCopy){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  Crypt::Rsa copy(rsa);

  static_cast<unsigned char*>(rsa.message)[0] = 'X';
  static_cast<unsigned char*>(rsa.cipher)[0] ^= 0xFF;

  EXPECT_NE(
    static_cast<unsigned char*>(copy.message)[0],
    static_cast<unsigned char*>(rsa.message)[0]
  );

  EXPECT_NE(
    static_cast<unsigned char*>(copy.cipher)[0],
    static_cast<unsigned char*>(rsa.cipher)[0]
  );
};



//// ==================== ////
//// ====== Move ======== ////
//// ==================== ////
TEST(RsaMove, HandlesMoveConstructor){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  void* message_ptr = rsa.message;
  void* cipher_ptr = rsa.cipher;

  size_t message_size = rsa.message_size;
  size_t cipher_size = rsa.cipher_size;

  Crypt::Rsa moved(std::move(rsa));

  EXPECT_EQ(moved.message, message_ptr);
  EXPECT_EQ(moved.cipher, cipher_ptr);

  EXPECT_EQ(moved.message_size, message_size);
  EXPECT_EQ(moved.cipher_size, cipher_size);

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.cipher, nullptr);

  EXPECT_EQ(rsa.message_size, 0);
  EXPECT_EQ(rsa.cipher_size, 0);
};

TEST(RsaMove, HandlesMoveAssignment){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  void* message_ptr = rsa.message;
  void* cipher_ptr = rsa.cipher;

  size_t message_size = rsa.message_size;
  size_t cipher_size = rsa.cipher_size;

  Crypt::Rsa moved;

  moved = std::move(rsa);

  EXPECT_EQ(moved.message, message_ptr);
  EXPECT_EQ(moved.cipher, cipher_ptr);

  EXPECT_EQ(moved.message_size, message_size);
  EXPECT_EQ(moved.cipher_size, cipher_size);

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.cipher, nullptr);

  EXPECT_EQ(rsa.message_size, 0);
  EXPECT_EQ(rsa.cipher_size, 0);
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(RsaGettersSetters, HandlesP){
  Crypt::Rsa rsa;

  rsa.setP(21191);

  EXPECT_EQ(rsa.getP(), 21191);
  EXPECT_TRUE(rsa.pIsPrime());
};

TEST(RsaGettersSetters, HandlesQ){
  Crypt::Rsa rsa;

  rsa.setQ(48337);

  EXPECT_EQ(rsa.getQ(), 48337);
  EXPECT_TRUE(rsa.qIsPrime());
};

TEST(RsaGettersSetters, HandlesInvalidP){
  Crypt::Rsa rsa;

  rsa.setP(100);

  EXPECT_EQ(rsa.getP(), 100);
  EXPECT_FALSE(rsa.pIsPrime());
};

TEST(RsaGettersSetters, HandlesInvalidQ){
  Crypt::Rsa rsa;

  rsa.setQ(100);

  EXPECT_EQ(rsa.getQ(), 100);
  EXPECT_FALSE(rsa.qIsPrime());
};

TEST(RsaGettersSetters, HandlesE){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  EXPECT_EQ(rsa.getE(), 65537);
  EXPECT_TRUE(rsa.eIsValid());
  EXPECT_EQ(rsa.d, 608852033);
};

TEST(RsaGettersSetters, HandlesInvalidE){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(2);

  EXPECT_EQ(rsa.getE(), 0);
  EXPECT_EQ(rsa.d, 0);
  EXPECT_FALSE(rsa.eIsValid());
};

TEST(RsaGettersSetters, HandlesERevalidation){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  EXPECT_TRUE(rsa.eIsValid());
  EXPECT_EQ(rsa.d, 608852033);

  rsa.setP(21193);

  if(rsa.eIsValid())
    EXPECT_NE(rsa.d, 608852033);
  else
    EXPECT_EQ(rsa.d, 0);
};

TEST(RsaGettersSetters, HandlesMessage){
  Crypt::Rsa rsa;

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());

  std::pair<const void*, size_t> result = rsa.getMessage();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, message.size());
  EXPECT_EQ(
    std::memcmp(result.first, message.data(), message.size()),
    0
  );
};

TEST(RsaGettersSetters, HandlesMessageDeepCopy){
  Crypt::Rsa rsa;

  std::string message = "Hello World";
  std::string original = message;

  rsa.setMessage(message.data(), message.size());

  message[0] = 'X';

  EXPECT_EQ(
    std::memcmp(
      rsa.message,
      original.data(),
      original.size()
    ),
    0
  );
};

TEST(RsaGettersSetters, HandlesMessageReplacement){
  Crypt::Rsa rsa;

  std::string first = "First Message";
  std::string second = "Second Message";

  rsa.setMessage(first.data(), first.size());
  rsa.setMessage(second.data(), second.size());

  EXPECT_EQ(rsa.message_size, second.size());
  EXPECT_EQ(
    std::memcmp(
      rsa.message,
      second.data(),
      second.size()
    ),
    0
  );
};

TEST(RsaGettersSetters, HandlesEmptyMessage){
  Crypt::Rsa rsa;

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.setMessage(nullptr, 0);

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.message_size, 0);
};

TEST(RsaGettersSetters, HandlesCipher){
  Crypt::Rsa rsa;

  std::array<unsigned char, 8> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
  };

  rsa.setCipher(cipher.data(), cipher.size());

  std::pair<const void*, size_t> result = rsa.getCipher();

  ASSERT_NE(result.first, nullptr);
  EXPECT_EQ(result.second, cipher.size());
  EXPECT_EQ(
    std::memcmp(result.first, cipher.data(), cipher.size()),
    0
  );
};

TEST(RsaGettersSetters, HandlesCipherDeepCopy){
  Crypt::Rsa rsa;

  std::array<unsigned char, 8> cipher = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08
  };

  std::array<unsigned char, 8> original = cipher;

  rsa.setCipher(cipher.data(), cipher.size());

  cipher[0] = 0xFF;

  EXPECT_EQ(
    std::memcmp(
      rsa.cipher,
      original.data(),
      original.size()
    ),
    0
  );
};

TEST(RsaGettersSetters, HandlesEmptyCipher){
  Crypt::Rsa rsa;

  std::array<unsigned char, 4> cipher = {
    0x01, 0x02, 0x03, 0x04
  };

  rsa.setCipher(cipher.data(), cipher.size());
  rsa.setCipher(nullptr, 0);

  EXPECT_EQ(rsa.cipher, nullptr);
  EXPECT_EQ(rsa.cipher_size, 0);
};



//// ====================== ////
//// ====== RSA Data ====== ////
//// ====================== ////
TEST(RsaData, HandlesN){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);

  EXPECT_EQ(rsa.n, 1024309367);
};

TEST(RsaData, HandlesFibN){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);

  EXPECT_EQ(rsa.fib_n, 1024239840);
};

TEST(RsaData, HandlesD){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  EXPECT_EQ(rsa.d, 608852033);
};

TEST(RsaData, HandlesEqualPQ){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(21191);

  EXPECT_EQ(rsa.n, 0);
  EXPECT_EQ(rsa.fib_n, 0);
  EXPECT_FALSE(rsa.eIsValid());
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
TEST(RsaCrypt, HandlesMessage){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  ASSERT_NE(rsa.cipher, nullptr);

  EXPECT_EQ(
    rsa.cipher_size,
    message.size() * sizeof(uint32_t)
  );
};

TEST(RsaCrypt, CipherDiffersFromMessage){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  ASSERT_NE(rsa.cipher, nullptr);

  EXPECT_FALSE(
    rsa.cipher_size == message.size() &&
    std::memcmp(
      rsa.cipher,
      message.data(),
      message.size()
    ) == 0
  );
};

TEST(RsaCrypt, HandlesEmptyMessage){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  rsa.crypt();

  EXPECT_EQ(rsa.cipher, nullptr);
  EXPECT_EQ(rsa.cipher_size, 0);
};

TEST(RsaCrypt, HandlesBinaryData){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03,
    0x10, 0x20, 0x42, 0x7F,
    0x80, 0xAA, 0xFE, 0xFF
  };

  rsa.setMessage(data.data(), data.size());
  rsa.crypt();

  EXPECT_EQ(
    rsa.cipher_size,
    data.size() * sizeof(uint32_t)
  );
};



//// ===================== ////
//// ====== Encrypt ====== ////
//// ===================== ////
TEST(RsaEncrypt, HandlesMessage){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();
  rsa.encrypt();

  std::pair<const void*, size_t> result = rsa.getMessage();

  ASSERT_NE(result.first, nullptr);

  std::string recreated(
    static_cast<const char*>(result.first),
    result.second
  );

  EXPECT_EQ(message, recreated);
};

TEST(RsaEncrypt, HandlesSeparateObjects){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::string message = "Hello World";

  rsa.setMessage(message.data(), message.size());
  rsa.crypt();

  std::pair<const void*, size_t> cipher = rsa.getCipher();

  Crypt::Rsa rsa2;

  rsa2.setP(21191);
  rsa2.setQ(48337);
  rsa2.setE(65537);

  rsa2.setCipher(cipher.first, cipher.second);
  rsa2.encrypt();

  std::pair<const void*, size_t> result = rsa2.getMessage();

  ASSERT_NE(result.first, nullptr);

  std::string recreated(
    static_cast<const char*>(result.first),
    result.second
  );

  EXPECT_EQ(message, recreated);
};

TEST(RsaEncrypt, HandlesBinaryData){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03,
    0x10, 0x20, 0x42, 0x7F,
    0x80, 0xAA, 0xFE, 0xFF
  };

  rsa.setMessage(data.data(), data.size());
  rsa.crypt();
  rsa.encrypt();

  ASSERT_NE(rsa.message, nullptr);
  EXPECT_EQ(rsa.message_size, data.size());

  EXPECT_EQ(
    std::memcmp(
      rsa.message,
      data.data(),
      data.size()
    ),
    0
  );
};

TEST(RsaEncrypt, HandlesEmptyCipher){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  rsa.encrypt();

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.message_size, 0);
};

TEST(RsaEncrypt, HandlesInvalidCipherSize){
  Crypt::Rsa rsa;

  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);

  std::array<unsigned char, 3> cipher = {
    0x01, 0x02, 0x03
  };

  rsa.setCipher(cipher.data(), cipher.size());
  rsa.encrypt();

  EXPECT_EQ(rsa.message, nullptr);
  EXPECT_EQ(rsa.message_size, 0);
};



//// =================== ////
//// ====== Logic ====== ////
//// =================== ////
TEST(RsaLogic, HandlesEquality){
  Crypt::Rsa rsa1;
  Crypt::Rsa rsa2;

  rsa1.setP(21191);
  rsa1.setQ(48337);
  rsa1.setE(65537);

  rsa2.setP(21191);
  rsa2.setQ(48337);
  rsa2.setE(65537);

  EXPECT_TRUE(rsa1 == rsa2);
  EXPECT_FALSE(rsa1 != rsa2);
};

TEST(RsaLogic, HandlesInequality){
  Crypt::Rsa rsa1;
  Crypt::Rsa rsa2;

  rsa1.setP(21191);
  rsa1.setQ(48337);
  rsa1.setE(65537);

  rsa2.setP(21191);
  rsa2.setQ(48337);
  rsa2.setE(17);

  EXPECT_FALSE(rsa1 == rsa2);
  EXPECT_TRUE(rsa1 != rsa2);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
TEST(RsaHelpers, HandlesPrime){
  Crypt::Rsa rsa;

  EXPECT_TRUE(rsa.check_is_prime(2));
  EXPECT_TRUE(rsa.check_is_prime(3));
  EXPECT_TRUE(rsa.check_is_prime(5));
  EXPECT_TRUE(rsa.check_is_prime(21191));
  EXPECT_TRUE(rsa.check_is_prime(48337));
};

TEST(RsaHelpers, HandlesNotPrime){
  Crypt::Rsa rsa;

  EXPECT_FALSE(rsa.check_is_prime(0));
  EXPECT_FALSE(rsa.check_is_prime(1));
  EXPECT_FALSE(rsa.check_is_prime(4));
  EXPECT_FALSE(rsa.check_is_prime(9));
  EXPECT_FALSE(rsa.check_is_prime(100));
};

TEST(RsaHelpers, HandlesGCD){
  Crypt::Rsa rsa;

  EXPECT_TRUE(rsa.gcdTest(65537, 1024239840));
  EXPECT_FALSE(rsa.gcdTest(2, 1024239840));
};

TEST(RsaHelpers, HandlesModPow){
  Crypt::Rsa rsa;

  EXPECT_EQ(rsa.modPow(2, 10, 1000), 24);
  EXPECT_EQ(rsa.modPow(5, 0, 7), 1);
  EXPECT_EQ(rsa.modPow(72, 65537, 1024309367), 325479505);
};

TEST(RsaHelpers, HandlesCalculateD){
  Crypt::Rsa rsa;

  rsa.p = 21191;
  rsa.q = 48337;
  rsa.e = 65537;

  rsa.calculateFibN();
  rsa.calculateD();

  EXPECT_EQ(rsa.d, 608852033);
};
