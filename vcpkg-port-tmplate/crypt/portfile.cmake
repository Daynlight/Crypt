vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO Daynlight/Crypt

  REF 3096f4d874331bef38963926081cb93a42fd2563
  SHA512 "0"
  HEAD_REF main
)

vcpkg_cmake_configure(
  SOURCE_PATH "${SOURCE_PATH}"
  OPTIONS
    -DCRYPT_BUILD_EXAMPLE=OFF
    -DCRYPT_BUILD_TESTS=OFF
)

vcpkg_cmake_install()
