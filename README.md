# @foxwallet/react-native-wallet-utils

This React Native library packages practical crypto functions written in Rust/Go for FoxWallet.

## Getting started

```shell script
yarn add @foxwallet/react-native-wallet-utils
cd ios && pod install && cd ..
```

## Usage

All the functions could be find in the `index.d.ts` file. They are wrapped with async behaviors, since we need access to Rust runtime, be sure to use `await` or `then` to access the result.

```javascript
import WalletCore from "@foxwallet/react-native-wallet-utils";

async function getRandomPhrase() {
  const newRandomPhrase = WalletCore.randomPhrase(12);
}
```

## Build and Develop

### Requirements

- `node.js` (`>=10`)
- `yarn` (tested on `1.22.19`)
- `rustup` (tested on `rustup 1.27.0`)
- `rustc` (tested on `rustc 1.77.2`)
- `cargo` (tested on `cargo 1.77.2`)
- `android_ndk` (tested on `r23`, can be downloaded [here](https://developer.android.com/ndk/downloads))
- `$NDK_HOME` envarionment variable set to ndk home directory (eg. `/usr/local/opt/android-ndk`)
- `go`

\* It's recommended to install **Android Studio** and use that to install the necessary build tools and SDKs for the Android version you want to test on. It's also the best way to test in the emulator.

### Setup

- Use the following script to install the required rust toolchains.

```shell script
./scripts/rust_init.sh

# rustup target add aarch64-apple-ios x86_64-apple-ios armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android

./scripts/go_init.sh
```

### Develop

After update the Rust/Go code, you need to change the following files for updating the interface to native android and ios code.

- ios/RustCore.h
- ios/WalletCore.m
- ios/WalletCore.swift
- android/src/main/java/com/foxwalet/core/WalletCoreModule.java
- index.js
- index.d.ts

### Test

- To run the rust test

```shell script
yarn test
```

### Build

- Use the following script to build the dynamic library for Android and static library for iOS.

```shell script
./scripts/rust_build.sh
./scripts/go_build.sh
```

