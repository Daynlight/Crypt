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
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
  TARGETS Crypt
  EXPORT CryptTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
  DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Crypt/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/Crypt"
  FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.hpp"
    PATTERN "*.inl"
)

install(
  EXPORT CryptTargets
  FILE CryptTargets.cmake
  NAMESPACE Crypt::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypt"
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CryptConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/CryptConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypt"
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CryptConfigVersion.cmake"
  VERSION 1.0.0
  COMPATIBILITY SameMajorVersion
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CryptConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CryptConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Crypt"
)
