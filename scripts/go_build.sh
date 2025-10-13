#!/bin/bash
source ./scripts/variables.sh

# Build iOS
cd ./go
gomobile bind -target=ios -ldflags="-s -w" -o ../ios/Frameworks/GoCore.xcframework

# Build android
gomobile bind -target=android -trimpath -ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384" -o ../spacemesh-go/spacemesh.aar

rm -f ../spacemesh-go/spacemesh-sources.jar
