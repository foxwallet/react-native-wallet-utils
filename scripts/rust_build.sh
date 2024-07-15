#!/bin/bash

source ./scripts/variables.sh

# Build iOS
cd ./rust

printf "Building iOS release targets...";

for i in "${IOS_ARCHS[@]}";
  do
    rustup target add "$i";
    cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target "$i" --release --no-default-features
done

lipo -create -output "../ios/release/lib${LIB_NAME}.a" target/aarch64-apple-ios/release/libcore.a

printf "Building iOS debug targets...";

for i in "${IOS_ARCHS_DEBUG[@]}";
  do
    rustup target add "$i";
    cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target "$i" --release --no-default-features
done

lipo -create -output "../ios/debug/lib${LIB_NAME}.a" target/x86_64-apple-ios/release/libcore.a target/aarch64-apple-ios/release/libcore.a

#  Build android

if [ -z ${NDK_HOME+x} ];
  then
    printf 'Please install android-ndk\n\n'
    printf 'from https://developer.android.com/ndk/downloads or with sdkmanager'
    exit 1
  else
    printf "Building Andriod targets...";
fi

printf "Building ARM64 Andriod targets...";
CC_aarch64_linux_android="${ANDROID_PREBUILD_BIN}/aarch64-linux-android${API_LEVEL}-clang" \
CXX_aarch64_linux_android="${ANDROID_PREBUILD_BIN}/aarch64-linux-android${API_LEVEL}-clang++" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_PREBUILD_BIN}/aarch64-linux-android${API_LEVEL}-clang" \
AR_aarch64_linux_android="${ANDROID_PREBUILD_BIN}/llvm-ar" \
RANLIB="${ANDROID_PREBUILD_BIN}/llvm-ranlib" \
  cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target aarch64-linux-android --release

printf "Building ARMv7 Andriod targets...";
CC_armv7_linux_androideabi="${ANDROID_PREBUILD_BIN}/armv7a-linux-androideabi${API_LEVEL}-clang" \
CXX_armv7_linux_androideabi="${ANDROID_PREBUILD_BIN}/armv7a-linux-androideabi${API_LEVEL}-clang++" \
CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${ANDROID_PREBUILD_BIN}/armv7a-linux-androideabi${API_LEVEL}-clang" \
AR_armv7_linux_androideabi="${ANDROID_PREBUILD_BIN}/llvm-ar" \
RANLIB="${ANDROID_PREBUILD_BIN}/llvm-ranlib"  \
  cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target armv7-linux-androideabi --release

printf "Building 32-bit x86  Andriod targets...";
CC_i686_linux_android="${ANDROID_PREBUILD_BIN}/i686-linux-android${API_LEVEL}-clang" \
CXX_i686_linux_android="${ANDROID_PREBUILD_BIN}/i686-linux-android${API_LEVEL}-clang++" \
CARGO_TARGET_I686_LINUX_ANDROID_LINKER="${ANDROID_PREBUILD_BIN}/i686-linux-android${API_LEVEL}-clang" \
AR_i686_linux_android="${ANDROID_PREBUILD_BIN}/llvm-ar" \
RANLIB="${ANDROID_PREBUILD_BIN}/llvm-ranlib" \
  cargo  +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target i686-linux-android --release

printf "Building 64-bit x86  Andriod targets...";
CC_x86_64_linux_android="${ANDROID_PREBUILD_BIN}/x86_64-linux-android${API_LEVEL}-clang" \
CXX_x86_64_linux_android="${ANDROID_PREBUILD_BIN}/x86_64-linux-android${API_LEVEL}-clang++" \
CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${ANDROID_PREBUILD_BIN}/x86_64-linux-android${API_LEVEL}-clang" \
AR_x86_64_linux_android="${ANDROID_PREBUILD_BIN}/llvm-ar" \
RANLIB="${ANDROID_PREBUILD_BIN}/llvm-ranlib" \
  cargo  +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-linux-android --release

for i in "${!ANDROID_ARCHS[@]}";
  do
    mkdir -p -v "../android/src/main/jniLibs/${ANDROID_FOLDER[$i]}"
    cp "./target/${ANDROID_ARCHS[$i]}/release/lib${LIB_NAME}.so" "../android/src/main/jniLibs/${ANDROID_FOLDER[$i]}/lib${LIB_NAME}.so"
done

