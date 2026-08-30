# Crypt
# Copyright 2026 Daynlight
# Licensed under the GNU General, Version 3.0.
# See LICENSE file for details.



cmake_minimum_required(VERSION 3.15)

option(CRYPT_BUILD_EXAMPLE "Build example" ON)
option(CRYPT_BUILD_TESTS "Build tests" ON)


set(CRYPT_VCPKG_INSTALLED_DIR "${CMAKE_SOURCE_DIR}/vendor/x64-linux")
list(APPEND CMAKE_PREFIX_PATH "${CRYPT_VCPKG_INSTALLED_DIR}")


add_subdirectory(Crypt)


####################
##### Examples #####
####################
if(CRYPT_BUILD_EXAMPLE)
  add_subdirectory(Examples)
endif()


#################
##### Tests #####
#################
if(CRYPT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(Tests)
endif()


###################
##### Install ##### 
###################
install(
  TARGETS Crypt
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

install(
  DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Crypt/"
  DESTINATION include/Crypt
  FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.hpp"
    PATTERN "*.inl"
)
