# Crypt
# Copyright 2026 Daynlight
# Licensed under the GNU General, Version 3.0.
# See LICENSE file for details.



cmake_minimum_required(VERSION 3.15)

project(CryptExamples LANGUAGES CXX)

find_package(fmt CONFIG REQUIRED)

set(src
  main.cpp
)

add_executable(CryptExamples ${src})
target_link_libraries(CryptExamples PUBLIC 
  Crypt::Crypt 
  fmt::fmt
)
