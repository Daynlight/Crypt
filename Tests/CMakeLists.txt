# Crypt
# Copyright 2026 Daynlight
# Licensed under the GNU General.
# See LICENSE file for details.



cmake_minimum_required(VERSION 3.15)

find_package(Threads REQUIRED)
find_package(GTest CONFIG REQUIRED)

set(tests_src
  Unit/Elliptic.cpp
  Unit/Des.cpp
  Unit/Aes.cpp
)

add_executable(unit_tests ${tests_src})


target_link_libraries(unit_tests PRIVATE 
  Crypt::Crypt
  GTest::gtest
  GTest::gtest_main
  GTest::gmock_main
)
target_include_directories(unit_tests PUBLIC Crypt)

include(GoogleTest)
gtest_discover_tests(unit_tests)
