// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>
#include <vector>
#include <cstring>

#define private public
#define protected public

#include <Crypt/Aes/Aes.h>

#undef private
#undef protected



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(AesConstructors, HandlesInitialization){
  Crypt::Aes aes;

  EXPECT_EQ(aes.getMessage().first, nullptr);
  EXPECT_EQ(aes.getMessage().second, 0);

  EXPECT_EQ(aes.getCipher().first, nullptr);
  EXPECT_EQ(aes.getCipher().second, 0);

  EXPECT_EQ(aes.getKey().first, nullptr);
  EXPECT_EQ(aes.getKey().second, 0);
};

//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(AesCopy, HandlesCopyConstructor){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  Crypt::Aes copy(aes);

  std::pair<const void*, size_t> original_message = aes.getMessage();
  std::pair<const void*, size_t> copied_message = copy.getMessage();

  std::pair<const void*, size_t> original_key = aes.getKey();
  std::pair<const void*, size_t> copied_key = copy.getKey();

  std::pair<const void*, size_t> original_cipher = aes.getCipher();
  std::pair<const void*, size_t> copied_cipher = copy.getCipher();

  EXPECT_NE(original_message.first, copied_message.first);
  EXPECT_NE(original_key.first, copied_key.first);
  EXPECT_NE(original_cipher.first, copied_cipher.first);

  EXPECT_EQ(original_message.second, copied_message.second);
  EXPECT_EQ(original_key.second, copied_key.second);
  EXPECT_EQ(original_cipher.second, copied_cipher.second);

  EXPECT_EQ(std::memcmp(original_message.first, copied_message.first, original_message.second), 0);
  EXPECT_EQ(std::memcmp(original_key.first, copied_key.first, original_key.second), 0);
  EXPECT_EQ(std::memcmp(original_cipher.first, copied_cipher.first, original_cipher.second), 0);
};

TEST(AesCopy, HandlesCopyAssignment){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  Crypt::Aes copy;
  copy = aes;

  std::pair<const void*, size_t> original_message = aes.getMessage();
  std::pair<const void*, size_t> copied_message = copy.getMessage();

  std::pair<const void*, size_t> original_key = aes.getKey();
  std::pair<const void*, size_t> copied_key = copy.getKey();

  std::pair<const void*, size_t> original_cipher = aes.getCipher();
  std::pair<const void*, size_t> copied_cipher = copy.getCipher();

  EXPECT_NE(original_message.first, copied_message.first);
  EXPECT_NE(original_key.first, copied_key.first);
  EXPECT_NE(original_cipher.first, copied_cipher.first);

  EXPECT_EQ(std::memcmp(original_message.first, copied_message.first, original_message.second), 0);
  EXPECT_EQ(std::memcmp(original_key.first, copied_key.first, original_key.second), 0);
  EXPECT_EQ(std::memcmp(original_cipher.first, copied_cipher.first, original_cipher.second), 0);
};

//// ==================== ////
//// ====== Move ======== ////
//// ==================== ////
TEST(AesMove, HandlesMoveConstructor){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  const void* message_ptr = aes.getMessage().first;
  const void* key_ptr = aes.getKey().first;
  const void* cipher_ptr = aes.getCipher().first;

  Crypt::Aes moved(std::move(aes));

  EXPECT_EQ(moved.getMessage().first, message_ptr);
  EXPECT_EQ(moved.getKey().first, key_ptr);
  EXPECT_EQ(moved.getCipher().first, cipher_ptr);

  EXPECT_EQ(aes.getMessage().first, nullptr);
  EXPECT_EQ(aes.getKey().first, nullptr);
  EXPECT_EQ(aes.getCipher().first, nullptr);

  EXPECT_EQ(aes.getMessage().second, 0);
  EXPECT_EQ(aes.getKey().second, 0);
  EXPECT_EQ(aes.getCipher().second, 0);
};

TEST(AesMove, HandlesMoveAssignment){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  const void* message_ptr = aes.getMessage().first;
  const void* key_ptr = aes.getKey().first;
  const void* cipher_ptr = aes.getCipher().first;

  Crypt::Aes moved;
  moved = std::move(aes);

  EXPECT_EQ(moved.getMessage().first, message_ptr);
  EXPECT_EQ(moved.getKey().first, key_ptr);
  EXPECT_EQ(moved.getCipher().first, cipher_ptr);

  EXPECT_EQ(aes.getMessage().first, nullptr);
  EXPECT_EQ(aes.getKey().first, nullptr);
  EXPECT_EQ(aes.getCipher().first, nullptr);

  EXPECT_EQ(aes.getMessage().second, 0);
  EXPECT_EQ(aes.getKey().second, 0);
  EXPECT_EQ(aes.getCipher().second, 0);
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(AesGettersSetters, HandlesMessage){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  aes.setMessage(message.data(), message.size());

  std::pair<const void*, size_t> get_message = aes.getMessage();
  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(message, recovered_message);
  EXPECT_EQ(message.size(), get_message.second);
};

TEST(AesGettersSetters, HandlesCipher){
  Crypt::Aes aes;

  std::string cipher = "Hello World Cipher";
  aes.setCipher(cipher.data(), cipher.size());

  std::pair<const void*, size_t> get_cipher = aes.getCipher();
  std::string recovered_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  EXPECT_EQ(cipher, recovered_cipher);
  EXPECT_EQ(cipher.size(), get_cipher.second);
};

TEST(AesGettersSetters, HandlesKey){
  Crypt::Aes aes;

  std::string key = "Very Long Secret Key";
  aes.setKey(key.data(), key.size());

  std::pair<const void*, size_t> get_key = aes.getKey();
  std::string recovered_key(static_cast<const char*>(get_key.first), get_key.second);

  EXPECT_EQ(key, recovered_key);
  EXPECT_EQ(key.size(), get_key.second);
};

TEST(AesGettersSetters, HandlesEmptyMessage){
  Crypt::Aes aes;

  aes.setMessage(nullptr, 0);

  std::pair<const void*, size_t> get_message = aes.getMessage();

  EXPECT_EQ(get_message.first, nullptr);
  EXPECT_EQ(get_message.second, 0);
};

TEST(AesGettersSetters, HandlesEmptyCipher){
  Crypt::Aes aes;

  aes.setCipher(nullptr, 0);

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  EXPECT_EQ(get_cipher.first, nullptr);
  EXPECT_EQ(get_cipher.second, 0);
};

TEST(AesGettersSetters, HandlesEmptyKey){
  Crypt::Aes aes;

  aes.setKey(nullptr, 0);

  std::pair<const void*, size_t> get_key = aes.getKey();

  EXPECT_EQ(get_key.first, nullptr);
  EXPECT_EQ(get_key.second, 0);
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
TEST(AesCryptEncrypt, HandlesMessage){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  ASSERT_GT(get_cipher.second, 0);

  std::string cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  EXPECT_NE(cipher, message);

  Crypt::Aes aes2;

  aes2.setCipher(cipher.data(), cipher.size());
  aes2.setKey(key.data(), key.size());
  aes2.encrypt();

  std::pair<const void*, size_t> get_message = aes2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(AesCryptEncrypt, HandlesLongKey){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "This Is A Very Long Secret Password For AES With Arbitrary Key Size";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  ASSERT_GT(get_cipher.second, 0);

  Crypt::Aes aes2;

  aes2.setCipher(get_cipher.first, get_cipher.second);
  aes2.setKey(key.data(), key.size());
  aes2.encrypt();

  std::pair<const void*, size_t> get_message = aes2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(AesCryptEncrypt, HandlesShortKey){
  Crypt::Aes aes;

  std::string message = "Hello World Message";
  std::string key = "A";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  ASSERT_GT(get_cipher.second, 0);

  Crypt::Aes aes2;

  aes2.setCipher(get_cipher.first, get_cipher.second);
  aes2.setKey(key.data(), key.size());
  aes2.encrypt();

  std::pair<const void*, size_t> get_message = aes2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(AesCryptEncrypt, HandlesSixteenByteMessage){
  Crypt::Aes aes;

  std::string message = "1234567890ABCDEF";
  std::string key = "HiddenKey";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  EXPECT_EQ(get_cipher.second, 32);

  Crypt::Aes aes2;

  aes2.setCipher(get_cipher.first, get_cipher.second);
  aes2.setKey(key.data(), key.size());
  aes2.encrypt();

  std::pair<const void*, size_t> get_message = aes2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(AesCryptEncrypt, HandlesBinaryData){
  Crypt::Aes aes;

  std::vector<unsigned char> message = {0x00, 0x01, 0x02, 0x03, 0xFF, 0x00, 0xAB, 0xCD, 0x42, 0x00, 0x69, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAA};
  std::string key = "Binary Data Secret Key";

  aes.setMessage(message.data(), message.size());
  aes.setKey(key.data(), key.size());
  aes.crypt();

  std::pair<const void*, size_t> get_cipher = aes.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);

  Crypt::Aes aes2;

  aes2.setCipher(get_cipher.first, get_cipher.second);
  aes2.setKey(key.data(), key.size());
  aes2.encrypt();

  std::pair<const void*, size_t> get_message = aes2.getMessage();

  ASSERT_NE(get_message.first, nullptr);
  ASSERT_EQ(get_message.second, message.size());

  const auto* recovered = static_cast<const unsigned char*>(get_message.first);

  for(size_t i = 0; i < message.size(); ++i) EXPECT_EQ(recovered[i], message[i]);
};

TEST(AesCryptEncrypt, HandlesDifferentKeys){
  Crypt::Aes aes1;
  Crypt::Aes aes2;

  std::string message = "Hello World Message";
  std::string key1 = "First Secret Key";
  std::string key2 = "Second Secret Key";

  aes1.setMessage(message.data(), message.size());
  aes1.setKey(key1.data(), key1.size());
  aes1.crypt();

  aes2.setMessage(message.data(), message.size());
  aes2.setKey(key2.data(), key2.size());
  aes2.crypt();

  std::pair<const void*, size_t> cipher1 = aes1.getCipher();
  std::pair<const void*, size_t> cipher2 = aes2.getCipher();

  ASSERT_EQ(cipher1.second, cipher2.second);

  std::string first(static_cast<const char*>(cipher1.first), cipher1.second);
  std::string second(static_cast<const char*>(cipher2.first), cipher2.second);

  EXPECT_NE(first, second);
};

TEST(AesCryptEncrypt, HandlesSameKey){
  Crypt::Aes aes1;
  Crypt::Aes aes2;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  aes1.setMessage(message.data(), message.size());
  aes1.setKey(key.data(), key.size());
  aes1.crypt();

  aes2.setMessage(message.data(), message.size());
  aes2.setKey(key.data(), key.size());
  aes2.crypt();

  std::pair<const void*, size_t> cipher1 = aes1.getCipher();
  std::pair<const void*, size_t> cipher2 = aes2.getCipher();

  ASSERT_EQ(cipher1.second, cipher2.second);

  std::string first(static_cast<const char*>(cipher1.first), cipher1.second);
  std::string second(static_cast<const char*>(cipher2.first), cipher2.second);

  EXPECT_EQ(first, second);
};

TEST(AesCryptEncrypt, HandlesInvalidCipherSize){
  Crypt::Aes aes;

  std::string cipher = "123456789012345";
  std::string key = "HiddenKey";

  aes.setCipher(cipher.data(), cipher.size());
  aes.setKey(key.data(), key.size());
  aes.encrypt();

  EXPECT_EQ(aes.getMessage().first, nullptr);
  EXPECT_EQ(aes.getMessage().second, 0);
};

TEST(AesCryptEncrypt, HandlesMissingKey){
  Crypt::Aes aes;

  std::string message = "Hello World Message";

  aes.setMessage(message.data(), message.size());
  aes.crypt();

  EXPECT_EQ(aes.getCipher().first, nullptr);
  EXPECT_EQ(aes.getCipher().second, 0);
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
TEST(AesHelpers, HandlesSubBytes){
  Crypt::Aes aes;

  uint8_t state[4][4] = {};

  aes.subBytes(state);

  for(size_t row = 0; row < 4; ++row)
    for(size_t col = 0; col < 4; ++col)
      EXPECT_EQ(state[row][col], 0x63);

  aes.invSubBytes(state);

  for(size_t row = 0; row < 4; ++row)
    for(size_t col = 0; col < 4; ++col)
      EXPECT_EQ(state[row][col], 0x00);
};

TEST(AesHelpers, HandlesShiftRows){
  Crypt::Aes aes;

  uint8_t state[4][4] = {
    {0x00, 0x01, 0x02, 0x03},
    {0x04, 0x05, 0x06, 0x07},
    {0x08, 0x09, 0x0A, 0x0B},
    {0x0C, 0x0D, 0x0E, 0x0F}
  };

  aes.shiftRows(state);

  EXPECT_EQ(state[0][0], 0x00);
  EXPECT_EQ(state[0][1], 0x01);
  EXPECT_EQ(state[0][2], 0x02);
  EXPECT_EQ(state[0][3], 0x03);

  EXPECT_EQ(state[1][0], 0x05);
  EXPECT_EQ(state[1][1], 0x06);
  EXPECT_EQ(state[1][2], 0x07);
  EXPECT_EQ(state[1][3], 0x04);

  EXPECT_EQ(state[2][0], 0x0A);
  EXPECT_EQ(state[2][1], 0x0B);
  EXPECT_EQ(state[2][2], 0x08);
  EXPECT_EQ(state[2][3], 0x09);

  EXPECT_EQ(state[3][0], 0x0F);
  EXPECT_EQ(state[3][1], 0x0C);
  EXPECT_EQ(state[3][2], 0x0D);
  EXPECT_EQ(state[3][3], 0x0E);

  aes.invShiftRows(state);

  for(size_t row = 0; row < 4; ++row)
    for(size_t col = 0; col < 4; ++col)
      EXPECT_EQ(state[row][col], static_cast<uint8_t>(row * 4 + col));
};

TEST(AesHelpers, HandlesGmul){
  Crypt::Aes aes;

  EXPECT_EQ(aes.gmul(0x57, 0x13), 0xFE);
  EXPECT_EQ(aes.gmul(0x57, 0x01), 0x57);
  EXPECT_EQ(aes.gmul(0x57, 0x00), 0x00);
};

TEST(AesHelpers, HandlesMixColumns){
  Crypt::Aes aes;

  uint8_t state[4][4] = {
    {0xDB, 0x00, 0x00, 0x00},
    {0x13, 0x00, 0x00, 0x00},
    {0x53, 0x00, 0x00, 0x00},
    {0x45, 0x00, 0x00, 0x00}
  };

  aes.mixColumns(state);

  EXPECT_EQ(state[0][0], 0x8E);
  EXPECT_EQ(state[1][0], 0x4D);
  EXPECT_EQ(state[2][0], 0xA1);
  EXPECT_EQ(state[3][0], 0xBC);

  aes.invMixColumns(state);

  EXPECT_EQ(state[0][0], 0xDB);
  EXPECT_EQ(state[1][0], 0x13);
  EXPECT_EQ(state[2][0], 0x53);
  EXPECT_EQ(state[3][0], 0x45);
};

TEST(AesHelpers, HandlesLoadStoreBlock){
  Crypt::Aes aes;

  unsigned char input[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
  };

  uint8_t state[4][4];
  unsigned char output[16];

  aes.loadBlock(input, state);

  EXPECT_EQ(state[0][0], 0x00);
  EXPECT_EQ(state[1][0], 0x01);
  EXPECT_EQ(state[2][0], 0x02);
  EXPECT_EQ(state[3][0], 0x03);

  EXPECT_EQ(state[0][1], 0x04);
  EXPECT_EQ(state[1][1], 0x05);
  EXPECT_EQ(state[2][1], 0x06);
  EXPECT_EQ(state[3][1], 0x07);

  EXPECT_EQ(state[0][2], 0x08);
  EXPECT_EQ(state[1][2], 0x09);
  EXPECT_EQ(state[2][2], 0x0A);
  EXPECT_EQ(state[3][2], 0x0B);

  EXPECT_EQ(state[0][3], 0x0C);
  EXPECT_EQ(state[1][3], 0x0D);
  EXPECT_EQ(state[2][3], 0x0E);
  EXPECT_EQ(state[3][3], 0x0F);

  aes.storeBlock(state, output);

  EXPECT_EQ(std::memcmp(input, output, 16), 0);
};

TEST(AesHelpers, HandlesRotWord){
  Crypt::Aes aes;

  EXPECT_EQ(aes.rotWord(0x09CF4F3C), 0xCF4F3C09);
};

TEST(AesHelpers, HandlesSubWord){
  Crypt::Aes aes;

  EXPECT_EQ(aes.subWord(0xCF4F3C09), 0x8A84EB01);
};

TEST(AesHelpers, HandlesDeriveKey){
  Crypt::Aes aes;

  std::string key = "HiddenKey";

  uint8_t first[16];
  uint8_t second[16];

  aes.deriveKey(key.data(), key.size(), first);
  aes.deriveKey(key.data(), key.size(), second);

  EXPECT_EQ(std::memcmp(first, second, 16), 0);
};

TEST(AesHelpers, HandlesDifferentDerivedKeys){
  Crypt::Aes aes;

  std::string key1 = "First Secret Key";
  std::string key2 = "Second Secret Key";

  uint8_t first[16];
  uint8_t second[16];

  aes.deriveKey(key1.data(), key1.size(), first);
  aes.deriveKey(key2.data(), key2.size(), second);

  EXPECT_NE(std::memcmp(first, second, 16), 0);
};