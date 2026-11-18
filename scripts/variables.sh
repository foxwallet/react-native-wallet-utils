#!/bin/bash

# Change this name to the rust library name
LIB_NAME=core
API_LEVEL=30

FOXWALLET_NDK_VERSION="${FOXWALLET_NDK_VERSION:-28.1.13356709}"
NDK_HOME="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}/ndk/${FOXWALLET_NDK_VERSION}}}"
# gomobile reads ANDROID_NDK_HOME; use the same NDK as the Rust build.
export ANDROID_NDK_HOME="${NDK_HOME}"

# Nightly toolchain used for -Z build-std.
NIGHTLY_TOOLCHAIN=nightly-2025-08-28

ANDROID_ARCHS=(aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android)
ANDROID_FOLDER=(arm64-v8a armeabi-v7a x86 x86_64)
ANDROID_BIN_PREFIX=(aarch64-linux-android armv7a-linux-androideabi i686-linux-android x86_64-linux-android)
IOS_ARCHS=(aarch64-apple-ios)
IOS_ARCHS_DEBUG=(aarch64-apple-ios x86_64-apple-ios)
OS_ARCH=$(uname | tr '[:upper:]' '[:lower:]')

ANDROID_PREBUILD_BIN=${NDK_HOME}/toolchains/llvm/prebuilt/${OS_ARCH}-x86_64/bin

#CC_aarch64_linux_android=${ANDROID_PREBUILD_BIN}/aarch64-linux-android29-clang
#CC_armv7_linux_androideabi=${ANDROID_PREBUILD_BIN}/armv7a-linux-androideabi29-clang
#CC_i686_linux_android=${ANDROID_PREBUILD_BIN}/i686-linux-android29-clang
#CC_x86_64_linux_android=${ANDROID_PREBUILD_BIN}/x86_64-linux-android29-clang

if command -v go >/dev/null 2>&1; then
    GOPATH_VALUE=$(go env GOPATH)
    export PATH="$PATH:$GOPATH_VALUE/bin"
fi

