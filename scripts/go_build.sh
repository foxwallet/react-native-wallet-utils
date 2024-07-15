#!/bin/bash
source ./scripts/variables.sh

# Build iOS
cd ./go
gomobile bind -target=ios -ldflags="-s -w" -o ../ios/Frameworks/GoCore.xcframework

# Build android
gomobile bind -target=android -trimpath -ldflags "-s -w" -o ../spacemesh-go/spacemesh.aar

rm -f ../spacemesh-go/spacemesh-source.jar
