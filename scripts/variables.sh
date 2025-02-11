#!/bin/bash

# Change this name to the rust library name
LIB_NAME=core
API_LEVEL=30

NDK_HOME=~/Library/Android/sdk/ndk/23.2.8568313

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

GOPATH_VALUE=$(go env GOPATH)
if [ -n "$GOPATH_VALUE" ]; then
    export PATH=$PATH:$GOPATH_VALUE/bin
    echo "Added $GOPATH_VALUE/bin to PATH"
else
    echo "GOPATH is empty"
    exit 1
fi

