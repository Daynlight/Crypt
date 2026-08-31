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

#include <Crypt/Sha/Sha.h>

#undef private
#undef protected



static std::string HashToHex(const std::array<uint8_t, 32>& hash){
  static constexpr char hex[] = "0123456789abcdef";

  std::string result;
  result.reserve(64);

  for(uint8_t byte : hash){
    result.push_back(hex[(byte >> 4) & 0x0F]);
    result.push_back(hex[byte & 0x0F]);
  };

  return result;
};



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
TEST(ShaConstructors, HandlesInitialization){
  Crypt::Sha sha;

  EXPECT_EQ(sha.data, nullptr);
  EXPECT_EQ(sha.data_size, 0);
  EXPECT_FALSE(sha.hashed);
};



//// ==================== ////
//// ====== Copy ======== ////
//// ==================== ////
TEST(ShaCopy, HandlesCopyConstructor){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());
  std::array<uint8_t, 32> original_hash = sha.getHash();

  Crypt::Sha copy(sha);

  EXPECT_NE(sha.data, copy.data);
  EXPECT_EQ(sha.data_size, copy.data_size);
  EXPECT_EQ(std::memcmp(sha.data, copy.data, sha.data_size), 0);

  EXPECT_EQ(copy.hash, original_hash);
  EXPECT_EQ(copy.hashed, sha.hashed);
};

TEST(ShaCopy, HandlesCopyAssignment){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());
  std::array<uint8_t, 32> original_hash = sha.getHash();

  Crypt::Sha copy;
  copy = sha;

  EXPECT_NE(sha.data, copy.data);
  EXPECT_EQ(sha.data_size, copy.data_size);
  EXPECT_EQ(std::memcmp(sha.data, copy.data, sha.data_size), 0);

  EXPECT_EQ(copy.hash, original_hash);
  EXPECT_EQ(copy.hashed, sha.hashed);
};



//// ==================== ////
//// ====== Move ======== ////
//// ==================== ////
TEST(ShaMove, HandlesMoveConstructor){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());
  sha.getHash();

  void* data_ptr = sha.data;
  size_t data_size = sha.data_size;

  Crypt::Sha moved(std::move(sha));

  EXPECT_EQ(moved.data, data_ptr);
  EXPECT_EQ(moved.data_size, data_size);

  EXPECT_EQ(sha.data, nullptr);
  EXPECT_EQ(sha.data_size, 0);
  EXPECT_FALSE(sha.hashed);
};

TEST(ShaMove, HandlesMoveAssignment){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());
  sha.getHash();

  void* data_ptr = sha.data;
  size_t data_size = sha.data_size;

  Crypt::Sha moved;
  moved = std::move(sha);

  EXPECT_EQ(moved.data, data_ptr);
  EXPECT_EQ(moved.data_size, data_size);

  EXPECT_EQ(sha.data, nullptr);
  EXPECT_EQ(sha.data_size, 0);
  EXPECT_FALSE(sha.hashed);
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
TEST(ShaGettersSetters, HandlesData){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());

  ASSERT_NE(sha.data, nullptr);
  EXPECT_EQ(sha.data_size, data.size());
  EXPECT_EQ(std::memcmp(sha.data, data.data(), data.size()), 0);
  EXPECT_FALSE(sha.hashed);
};

TEST(ShaGettersSetters, HandlesDeepCopy){
  Crypt::Sha sha;

  std::string data = "Hello World Message";
  std::string original = data;

  sha.setData(data.data(), data.size());

  data[0] = 'X';

  EXPECT_EQ(std::memcmp(sha.data, original.data(), original.size()), 0);
};

TEST(ShaGettersSetters, HandlesEmptyData){
  Crypt::Sha sha;

  sha.setData(nullptr, 0);

  EXPECT_EQ(sha.data, nullptr);
  EXPECT_EQ(sha.data_size, 0);
  EXPECT_FALSE(sha.hashed);
};

TEST(ShaGettersSetters, HandlesDataReplacement){
  Crypt::Sha sha;

  std::string first = "First Message";
  std::string second = "Second Message";

  sha.setData(first.data(), first.size());
  sha.getHash();

  EXPECT_TRUE(sha.hashed);

  sha.setData(second.data(), second.size());

  EXPECT_FALSE(sha.hashed);
  EXPECT_EQ(sha.data_size, second.size());
  EXPECT_EQ(std::memcmp(sha.data, second.data(), second.size()), 0);
};



//// ==================== ////
//// ====== SHA-256 ===== ////
//// ==================== ////
TEST(Sha256, HandlesEmptyData){
  Crypt::Sha sha;

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
};

TEST(Sha256, HandlesABC){
  Crypt::Sha sha;

  std::string data = "abc";

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
};

TEST(Sha256, HandlesMessage){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "6f41841dd2ee5241f4c00f1593a83c0d53bea71f2c40db59b14a751045a30720");
};



//// ========================== ////
//// ====== Block Sizes ======= ////
//// ========================== ////
TEST(Sha256Blocks, Handles55Bytes){
  Crypt::Sha sha;

  std::string data(55, 'a');

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
};

TEST(Sha256Blocks, Handles56Bytes){
  Crypt::Sha sha;

  std::string data(56, 'a');

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
};

TEST(Sha256Blocks, Handles64Bytes){
  Crypt::Sha sha;

  std::string data(64, 'a');

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
};

TEST(Sha256Blocks, Handles65Bytes){
  Crypt::Sha sha;

  std::string data(65, 'a');

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
};



//// ======================= ////
//// ===== Binary Data ===== ////
//// ======================= ////
TEST(Sha256, HandlesBinaryData){
  Crypt::Sha sha;

  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03,
    0xFF, 0x00, 0xAB, 0xCD,
    0x42, 0x00, 0x69, 0x12,
    0x34, 0x56, 0x78, 0x90,
    0xAA
  };

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "6a1be20b99810545139c2aa86ea9783bf414fc6efd271f92c898b09f0f8ecfc7");
};



//// ====================== ////
//// ===== Large Data ===== ////
//// ====================== ////
TEST(Sha256, HandlesLargeData){
  Crypt::Sha sha;

  std::string data(1'000'000, 'a');

  sha.setData(data.data(), data.size());

  std::string hash = HashToHex(sha.getHash());

  EXPECT_EQ(hash, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
};



//// ======================= ////
//// ===== Hash State ====== ////
//// ======================= ////
TEST(Sha256, HandlesRepeatedGetHash){
  Crypt::Sha sha;

  std::string data = "Hello World Message";

  sha.setData(data.data(), data.size());

  std::array<uint8_t, 32> first = sha.getHash();
  std::array<uint8_t, 32> second = sha.getHash();

  EXPECT_TRUE(sha.hashed);
  EXPECT_EQ(first, second);
};

TEST(Sha256, HandlesDifferentData){
  Crypt::Sha sha1;
  Crypt::Sha sha2;

  std::string first = "First Message";
  std::string second = "Second Message";

  sha1.setData(first.data(), first.size());
  sha2.setData(second.data(), second.size());

  EXPECT_NE(sha1.getHash(), sha2.getHash());
};