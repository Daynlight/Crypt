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

#include <Crypt/Des/Des.h>

#undef private
#undef protected



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(DesConstructors, HandlesInitialization){
  Crypt::Des des;

  EXPECT_EQ(des.getMessage().first, nullptr);
  EXPECT_EQ(des.getMessage().second, 0);

  EXPECT_EQ(des.getCipher().first, nullptr);
  EXPECT_EQ(des.getCipher().second, 0);

  EXPECT_EQ(des.getKey().first, nullptr);
  EXPECT_EQ(des.getKey().second, 0);
};

//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(DesCopy, HandlesCopyConstructor){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  Crypt::Des copy(des);

  std::pair<const void*, size_t> original_message = des.getMessage();
  std::pair<const void*, size_t> copied_message = copy.getMessage();

  std::pair<const void*, size_t> original_key = des.getKey();
  std::pair<const void*, size_t> copied_key = copy.getKey();

  std::pair<const void*, size_t> original_cipher = des.getCipher();
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

TEST(DesCopy, HandlesCopyAssignment){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  Crypt::Des copy;
  copy = des;

  std::pair<const void*, size_t> original_message = des.getMessage();
  std::pair<const void*, size_t> copied_message = copy.getMessage();

  std::pair<const void*, size_t> original_key = des.getKey();
  std::pair<const void*, size_t> copied_key = copy.getKey();

  std::pair<const void*, size_t> original_cipher = des.getCipher();
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
TEST(DesMove, HandlesMoveConstructor){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  const void* message_ptr = des.getMessage().first;
  const void* key_ptr = des.getKey().first;
  const void* cipher_ptr = des.getCipher().first;

  Crypt::Des moved(std::move(des));

  EXPECT_EQ(moved.getMessage().first, message_ptr);
  EXPECT_EQ(moved.getKey().first, key_ptr);
  EXPECT_EQ(moved.getCipher().first, cipher_ptr);

  EXPECT_EQ(des.getMessage().first, nullptr);
  EXPECT_EQ(des.getKey().first, nullptr);
  EXPECT_EQ(des.getCipher().first, nullptr);

  EXPECT_EQ(des.getMessage().second, 0);
  EXPECT_EQ(des.getKey().second, 0);
  EXPECT_EQ(des.getCipher().second, 0);
};

TEST(DesMove, HandlesMoveAssignment){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  const void* message_ptr = des.getMessage().first;
  const void* key_ptr = des.getKey().first;
  const void* cipher_ptr = des.getCipher().first;

  Crypt::Des moved;
  moved = std::move(des);

  EXPECT_EQ(moved.getMessage().first, message_ptr);
  EXPECT_EQ(moved.getKey().first, key_ptr);
  EXPECT_EQ(moved.getCipher().first, cipher_ptr);

  EXPECT_EQ(des.getMessage().first, nullptr);
  EXPECT_EQ(des.getKey().first, nullptr);
  EXPECT_EQ(des.getCipher().first, nullptr);

  EXPECT_EQ(des.getMessage().second, 0);
  EXPECT_EQ(des.getKey().second, 0);
  EXPECT_EQ(des.getCipher().second, 0);
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(DesGettersSetters, HandlesMessage){
  Crypt::Des des;

  std::string message = "Hello World Message";
  des.setMessage(message.data(), message.size());

  std::pair<const void*, size_t> get_message = des.getMessage();
  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(message, recovered_message);
  EXPECT_EQ(message.size(), get_message.second);
};

TEST(DesGettersSetters, HandlesCipher){
  Crypt::Des des;

  std::string cipher = "Hello World Cipher";
  des.setCipher(cipher.data(), cipher.size());

  std::pair<const void*, size_t> get_cipher = des.getCipher();
  std::string recovered_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  EXPECT_EQ(cipher, recovered_cipher);
  EXPECT_EQ(cipher.size(), get_cipher.second);
};

TEST(DesGettersSetters, HandlesKey){
  Crypt::Des des;

  std::string key = "Very Long Secret Key";
  des.setKey(key.data(), key.size());

  std::pair<const void*, size_t> get_key = des.getKey();
  std::string recovered_key(static_cast<const char*>(get_key.first), get_key.second);

  EXPECT_EQ(key, recovered_key);
  EXPECT_EQ(key.size(), get_key.second);
};

TEST(DesGettersSetters, HandlesEmptyMessage){
  Crypt::Des des;

  des.setMessage(nullptr, 0);

  std::pair<const void*, size_t> get_message = des.getMessage();

  EXPECT_EQ(get_message.first, nullptr);
  EXPECT_EQ(get_message.second, 0);
};

TEST(DesGettersSetters, HandlesEmptyCipher){
  Crypt::Des des;

  des.setCipher(nullptr, 0);

  std::pair<const void*, size_t> get_cipher = des.getCipher();

  EXPECT_EQ(get_cipher.first, nullptr);
  EXPECT_EQ(get_cipher.second, 0);
};

TEST(DesGettersSetters, HandlesEmptyKey){
  Crypt::Des des;

  des.setKey(nullptr, 0);

  std::pair<const void*, size_t> get_key = des.getKey();

  EXPECT_EQ(get_key.first, nullptr);
  EXPECT_EQ(get_key.second, 0);
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
TEST(DesCryptEncrypt, HandlesMessage){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  std::pair<const void*, size_t> get_cipher = des.getCipher();
  ASSERT_NE(get_cipher.first, nullptr);
  ASSERT_GT(get_cipher.second, 0);

  std::string cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  EXPECT_NE(cipher, message);

  Crypt::Des des2;

  des2.setCipher(cipher.data(), cipher.size());
  des2.setKey(key.data(), key.size());
  des2.encrypt();

  std::pair<const void*, size_t> get_message = des2.getMessage();
  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(DesCryptEncrypt, HandlesLongKey){
  Crypt::Des des;

  std::string message = "Hello World Message";
  std::string key = "This Is A Very Long Secret Password For DES";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  std::pair<const void*, size_t> get_cipher = des.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  ASSERT_GT(get_cipher.second, 0);

  Crypt::Des des2;

  des2.setCipher(get_cipher.first, get_cipher.second);
  des2.setKey(key.data(), key.size());
  des2.encrypt();

  std::pair<const void*, size_t> get_message = des2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(DesCryptEncrypt, HandlesEightByteMessage){
  Crypt::Des des;

  std::string message = "12345678";
  std::string key = "HiddenKey";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  std::pair<const void*, size_t> get_cipher = des.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);
  EXPECT_EQ(get_cipher.second, 16);

  Crypt::Des des2;

  des2.setCipher(get_cipher.first, get_cipher.second);
  des2.setKey(key.data(), key.size());
  des2.encrypt();

  std::pair<const void*, size_t> get_message = des2.getMessage();

  ASSERT_NE(get_message.first, nullptr);

  std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

  EXPECT_EQ(recovered_message, message);
};

TEST(DesCryptEncrypt, HandlesBinaryData){
  Crypt::Des des;

  std::vector<unsigned char> message = {0x00, 0x01, 0x02, 0x03, 0xFF, 0x00, 0xAB, 0xCD, 0x42, 0x00, 0x69};
  std::string key = "Binary Data Secret Key";

  des.setMessage(message.data(), message.size());
  des.setKey(key.data(), key.size());
  des.crypt();

  std::pair<const void*, size_t> get_cipher = des.getCipher();

  ASSERT_NE(get_cipher.first, nullptr);

  Crypt::Des des2;

  des2.setCipher(get_cipher.first, get_cipher.second);
  des2.setKey(key.data(), key.size());
  des2.encrypt();

  std::pair<const void*, size_t> get_message = des2.getMessage();

  ASSERT_NE(get_message.first, nullptr);
  ASSERT_EQ(get_message.second, message.size());

  const auto* recovered = static_cast<const unsigned char*>(get_message.first);

  for(size_t i = 0; i < message.size(); ++i) EXPECT_EQ(recovered[i], message[i]);
};

TEST(DesCryptEncrypt, HandlesDifferentKeys){
  Crypt::Des des1;
  Crypt::Des des2;

  std::string message = "Hello World Message";
  std::string key1 = "First Secret Key";
  std::string key2 = "Second Secret Key";

  des1.setMessage(message.data(), message.size());
  des1.setKey(key1.data(), key1.size());
  des1.crypt();

  des2.setMessage(message.data(), message.size());
  des2.setKey(key2.data(), key2.size());
  des2.crypt();

  std::pair<const void*, size_t> cipher1 = des1.getCipher();
  std::pair<const void*, size_t> cipher2 = des2.getCipher();

  ASSERT_EQ(cipher1.second, cipher2.second);

  std::string first(static_cast<const char*>(cipher1.first), cipher1.second);
  std::string second(static_cast<const char*>(cipher2.first), cipher2.second);

  EXPECT_NE(first, second);
};

TEST(DesCryptEncrypt, HandlesSameKey){
  Crypt::Des des1;
  Crypt::Des des2;

  std::string message = "Hello World Message";
  std::string key = "HiddenKey";

  des1.setMessage(message.data(), message.size());
  des1.setKey(key.data(), key.size());
  des1.crypt();

  des2.setMessage(message.data(), message.size());
  des2.setKey(key.data(), key.size());
  des2.crypt();

  std::pair<const void*, size_t> cipher1 = des1.getCipher();
  std::pair<const void*, size_t> cipher2 = des2.getCipher();

  ASSERT_EQ(cipher1.second, cipher2.second);

  std::string first(static_cast<const char*>(cipher1.first), cipher1.second);
  std::string second(static_cast<const char*>(cipher2.first), cipher2.second);

  EXPECT_EQ(first, second);
};
