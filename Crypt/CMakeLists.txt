# Crypt
# Copyright 2026 Daynlight
# Licensed under the GNU General, Version 3.0.
# See LICENSE file for details.



cmake_minimum_required(VERSION 3.15)

project(Crypt LANGUAGES CXX)

set(src
  Elliptic/Elliptic.cpp
  Des/Des.cpp
)

set(headers
  Elliptic/Elliptic.h
  Des/Des.h
  .
)

add_library(Crypt ${src})

add_library(Crypt::Crypt ALIAS Crypt)

target_include_directories(
  Crypt
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<INSTALL_INTERFACE:include>
)