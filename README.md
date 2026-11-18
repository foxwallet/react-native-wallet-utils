# @foxwallet/react-native-wallet-utils

This React Native library packages practical crypto functions written in Rust/Go for FoxWallet.

## Getting started

```shell script
yarn add @foxwallet/react-native-wallet-utils

# add to android/settings.gradle
include ':spacemesh-go'
project(':spacemesh-go').projectDir = new File(rootProject.projectDir, '../node_modules/@foxwallet/react-native-wallet-utils/spacemesh-go')

# add to ios/Podfile
pod 'react-native-wallet-utils', :path => "../node_modules/@foxwallet/react-native-wallet-utils", :configurations => ["Release", "Daily"]
pod 'react-native-wallet-utils-debug', :path => "../node_modules/@foxwallet/react-native-wallet-utils", :configurations => ["Debug"]

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
- Android NDK `28.1.13356709` (r28b), available through the Android SDK Manager
- Optional `$NDK_HOME` override for the NDK directory. By default, the build uses `$ANDROID_HOME/ndk/28.1.13356709` (or `$ANDROID_SDK_ROOT`, falling back to `~/Library/Android/sdk`). Rust and gomobile use this same NDK.
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

To rebuild only Android artifacts for Google Play:

```shell script
./scripts/rust_build.sh android
./scripts/go_build.sh android
```

If your shell exports an older NDK path, set `NDK_HOME` to the installed r28b
directory when running these commands. The scripts reject NDK versions below r28.

Both Android builds set 16 KB maximum and common page sizes. Publish the rebuilt
`android/src/main/jniLibs/*/libcore.so` and `spacemesh-go/spacemesh.aar` together,
then update the consuming app's wallet-utils dependency. Changing the app's NDK
version alone does not rebuild these precompiled files.

Check the 64-bit ELF LOAD and RELRO layouts, and confirm the rebuilt NDK version:

```shell script
python3 scripts/check_android_16kb.py android/src/main/jniLibs/arm64-v8a/libcore.so android/src/main/jniLibs/x86_64/libcore.so spacemesh-go/spacemesh.aar --min-ndk 28
```

The checker also accepts APK/AAB files. Static checks do not replace testing on
an Android device with `adb shell getconf PAGE_SIZE` returning `16384`.

## Aleo execution fee estimation

`aleoEstimateExecutionFee(request: string): Promise<string>` estimates fees locally with snarkVM 4.11.0. It does not generate a proof or submit a transaction. Android and iOS expose the same JSON interface. Rebuild the native libraries with `yarn build` after changing the Rust implementation.

The JSON request is:

```json
{
  "network": "mainnet",
  "blockHeight": 23715963,
  "programId": "credits.aleo",
  "functionName": "transfer_public",
  "programs": []
}
```

For custom programs, `programs` contains `{ "id": "example.aleo", "source": "...", "edition": 1 }` entries, ordered with transitive dependencies first and the root last. Do not include the built-in `credits.aleo`. Resolve source and edition from the same official RPC response (`/program/{id}?metadata=true`). The estimator selects the consensus rules at `blockHeight` (mainnet V4 onward), rather than assuming the latest software consensus version is active.

Optional `address` and `inputs: string[]` estimate the actual call using `execution_cost_for_call`, without a user private key. Without inputs, the estimator uses sampled values and a disposable key, matching the official SDK's generic execution estimation. Dynamic calls require actual inputs and all programs they invoke. Input-dependent assertions can also require actual inputs.

Success is JSON `{ "error": "", "data": { "baseFee": "2725", "storageFee": "...", "finalizeFee": "...", "blockHeight": 23715963, "consensusVersion": "V21" } }`; amounts are decimal strings in microcredits. These example amounts are not a fee schedule. Errors use the existing `{ "error": "...", "data": "" }` contract. Priority fees are separate. The special internal charge for `credits.aleo/split` is also separate from its estimated execution cost.

Run the offline estimator tests with `cargo test --manifest-path rust/Cargo.toml aleo::fee::tests -- --test-threads=1`.
