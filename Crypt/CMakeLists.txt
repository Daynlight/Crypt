# Crypt
# Copyright 2026 Daynlight
# Licensed under the GNU General, Version 3.0.
# See LICENSE file for details.



cmake_minimum_required(VERSION 3.15)

project(Crypt LANGUAGES CXX)

set(src
  Elliptic/Elliptic.cpp
)

set(headers
  Elliptic/Elliptic.h
  .
)

add_library(Crypt ${src})
target_include_directories(Crypt PUBLIC ${headers})
