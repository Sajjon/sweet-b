#
# arm.cmake: toolchain file for ARM testing in Travis CI
#
# This file is part of Sweet B, a safe, compact, embeddable elliptic curve
# cryptography library.
#
# Sweet B is provided under the terms of the included LICENSE file. All
# other rights are reserved.
#
# Copyright 2017 Wearable Inc.
#

SET(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
SET(CMAKE_C_FLAGS "-Os -mcpu=cortex-a5 -mthumb" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS "-static" CACHE STRING "" FORCE)
SET(SB_MUL_SIZE "4" CACHE STRING "")
